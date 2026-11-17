"""
lab.py - 靶场命令行客户端（零第三方依赖，只用 Python 标准库）

这个脚本就是练习者手里的「攻击机」。它做三件真实工具也做的事：
  1. 走正常 Kerberos 流程（login / ask / use），对应 kinit + 访问服务；
  2. 从泄露端点取到密钥（leak），对应 DCSync / 本地提权拿 SAM；
  3. 用泄露的密钥在【本地离线】封印票据（forge），对应 impacket ticketer.py
     或 mimikatz kerberos::golden —— 全程不请求 KDC，这正是票据伪造的要点。

服务端只负责用自己手里的密钥校验，不会替客户端生成任何伪造票据。
票据缓存放在 kerberos/.cache/，与真实 %TEMP%/*.kirbi、KRB5CCNAME 对应。

命令一览（python3 poc/lab.py help 可再看一次）：
  state                         查看域状态 / 日志 / 通关进度
  logs                          只打印两份日志对照
  login <user> <password>       AS-REQ，拿 TGT
  ask <spn>                     TGS-REQ，用缓存 TGT 换 TGS
  use <spn>                     AP-REQ，用缓存 TGS 访问服务
  klist                         查看缓存票据明文（PAC / SID / SPN / 生命周期）
  leak krbtgt                   模拟 DCSync，取 krbtgt 当前密钥
  leak service <spn>            模拟本地提权，取该服务账户密钥
  forge golden                  离线伪造 TGT（黄金票据）
  forge silver --spn <spn>      离线伪造 TGS（白银票据）
  pac on|off                    开关完整 PAC 签名校验
  reset                         重置 krbtgt 密码一次
  restart                       靶场回到初始状态
"""

import json
import os
import sys
import urllib.error
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "src"))
import krb  # noqa: E402

BASE = os.environ.get("LAB_URL", "http://127.0.0.1:8907")
CACHE = os.path.join(ROOT, ".cache")
os.makedirs(CACHE, exist_ok=True)


def http(method, path, data=None):
    """统一发 HTTP 请求并返回 JSON。服务端 4xx 也返回 JSON，照常解析。"""
    body = json.dumps(data or {}).encode() if method == "POST" else None
    req = urllib.request.Request(
        BASE + path,
        data=body,
        headers={"Content-Type": "application/json"},
        method=method,
    )
    try:
        with urllib.request.urlopen(req, timeout=6) as resp:
            return json.loads(resp.read().decode())
    except urllib.error.HTTPError as e:
        try:
            return json.loads(e.read().decode())
        except Exception:
            return {"ok": False, "reason": "http_%d" % e.code}
    except Exception as e:
        return {"ok": False, "reason": "connection_failed", "detail": str(e)}


def cache_path(name):
    return os.path.join(CACHE, name)


def save(name, value):
    with open(cache_path(name), "w", encoding="utf-8") as f:
        f.write(value if isinstance(value, str) else json.dumps(value, ensure_ascii=False))


def load(name, default=None):
    try:
        with open(cache_path(name), "r", encoding="utf-8") as f:
            return f.read()
    except OSError:
        return default


def load_keys():
    try:
        return json.loads(load("keys.json", "{}"))
    except Exception:
        return {}


def show(result, title=""):
    """打印一次 API 结果，并把新解锁的 flag 提到最显眼的位置。"""
    if title:
        print("\n=== %s ===" % title)
    for item in result.get("unlocked", []):
        print("  [FLAG L%d] %s" % (item["level"], item["flag"]))
        print("  [证据] %s" % item["evidence"])
    clean = {k: v for k, v in result.items() if k != "unlocked"}
    for field in ("tgt", "tgs"):
        value = clean.get(field)
        if isinstance(value, str) and len(value) > 40:
            clean[field] = value[:24] + "...（已截断，完整票据在 .cache/）"
    print("  " + json.dumps(clean, ensure_ascii=False, indent=2).replace("\n", "\n  "))
    return result


def need_key(keys, name, hint):
    """取密钥；没泄露过就明确报错，不允许脚本偷偷从服务端代造票据。"""
    value = keys.get(name)
    if not value:
        print("  [拒绝] 还没有 %s。请先执行：%s" % (name, hint))
        sys.exit(2)
    return value


def parse_groups(text):
    """把 512,513 这样的 RID 列表转成完整组 SID。"""
    out = []
    for rid in text.split(","):
        rid = rid.strip()
        if rid:
            out.append(krb.DOMAIN_SID + "-" + rid)
    return out


def cmd_forge(args):
    """离线伪造票据。整个函数不发任何 HTTP 请求，只用本地密钥做 HMAC 封印。"""
    kind = args[0] if args else ""
    opts = {}
    i = 1
    while i < len(args):
        if args[i].startswith("--"):
            opts[args[i][2:]] = args[i + 1] if i + 1 < len(args) else ""
            i += 2
        else:
            i += 1

    keys = load_keys()
    user = opts.get("user", "Administrator")
    sid = krb.DOMAIN_SID + "-" + str(krb.RID_ADMIN)
    groups = parse_groups(opts.get("groups", "513,512"))
    lifetime = krb.TEN_YEARS if opts.get("lifetime", "10y") == "10y" else krb.TEN_HOURS
    ts = int(__import__("time").time())

    if kind == "golden":
        key = opts.get("key") or need_key(keys, "krbtgt", "python3 poc/lab.py leak krbtgt")
        pac = krb.sign_pac(krb.pac_body(user, sid, groups, ts), key, key)
        tgt = {
            "type": "TGT",
            "realm": krb.REALM,
            "user": user,
            "sid": sid,
            "groups": groups,
            "pac": pac,
            "issued": ts,
            "lifetime": lifetime,
        }
        token = krb.seal(tgt, key)
        save("tgt", token)
        print("\n=== 离线伪造黄金票据（TGT）===")
        print("  密钥来源：krbtgt（DCSync）  未向 KDC 发送任何请求")
        print("  身份：%s  组：%s  有效期：%d 秒（域策略为 %d 秒）" %
              (user, ",".join(g.split("-")[-1] for g in groups), lifetime, krb.TEN_HOURS))
        print("  已写入 .cache/tgt，接下来：ask <spn> 换真 TGS，再 use <spn>")
        print("  票据指纹：%s" % krb.fingerprint(token))
        return

    if kind == "silver":
        spn = opts.get("spn")
        if not spn:
            print("  [用法] forge silver --spn cifs/files.lab.local")
            sys.exit(2)
        key = opts.get("key") or need_key(keys, spn, "python3 poc/lab.py leak service " + spn)
        pac = krb.pac_body(user, sid, groups, ts)
        pac["svc_sig"] = krb.mac(key, krb.canonical(pac).decode())
        pac["kdc_sig"] = "0" * 64
        tgs = {
            "type": "TGS",
            "realm": krb.REALM,
            "spn": spn,
            "user": user,
            "sid": sid,
            "groups": groups,
            "pac": pac,
            "issued": ts,
            "lifetime": krb.TEN_HOURS,
        }
        token = krb.seal(tgs, key)
        save("tgs", token)
        print("\n=== 离线伪造白银票据（TGS）===")
        print("  密钥来源：%s 的账户密钥（本地 SAM）  未向 KDC 发送任何请求" % spn)
        print("  身份：%s  组：%s  SPN：%s" %
              (user, ",".join(g.split("-")[-1] for g in groups), spn))
        print("  PAC kdc_sig 是伪造的 —— 只有开启完整 PAC 校验时才会被查出来")
        print("  已写入 .cache/tgs，接下来直接：use %s（注意没有 ask 这一步）" % spn)
        print("  票据指纹：%s" % krb.fingerprint(token))
        return

    print("  [用法] forge golden | forge silver --spn <spn>")


def cmd_klist():
    """模拟 klist：只解明文，不校验密钥，展示票据里到底写了什么。"""
    print("\n=== 票据缓存（klist）===")
    for name in ("tgt", "tgs"):
        token = load(name)
        if not token:
            print("  %s: （空）" % name)
            continue
        obj = krb.peek(token)
        print("  %s  指纹=%s" % (name, krb.fingerprint(token)))
        if obj:
            print("    type=%s  user=%s  spn=%s  lifetime=%ss" %
                  (obj.get("type"), obj.get("user"), obj.get("spn", "-"), obj.get("lifetime")))
            print("    groups=%s" % [g.split("-")[-1] for g in obj.get("groups", [])])
            pac = obj.get("pac", {})
            print("    PAC kdc_sig=%s...  svc_sig=%s..." %
                  (str(pac.get("kdc_sig", ""))[:12], str(pac.get("svc_sig", ""))[:12]))


def cmd_logs():
    """把两份日志并排打印，专门用来观察白银票据时 DC 侧的空白。"""
    d = http("GET", "/api/state")
    print("\n=== 域控 DC 安全日志 ===")
    for r in d.get("dc_logs", []):
        extra = "  " + r.get("note", "") if r.get("note") else ""
        print("  %s  %s  %-12s %-24s %s%s" %
              (r["time"], r["event"], r["user"], r["spn"], r.get("result", ""), extra))
    if not d.get("dc_logs"):
        print("  （空）")
    print("\n=== 目标服务器本地日志 ===")
    for r in d.get("host_logs", []):
        print("  %s  %s  %-12s %-24s %s  %s" %
              (r["time"], r["event"], r["user"], r["spn"], r.get("result", ""),
               r.get("reason", r.get("note", ""))))
    if not d.get("host_logs"):
        print("  （空）")
    print("\n  krbtgt 重置 %d 次 / PAC 严格=%s" % (d.get("resets", 0), d.get("pac_strict")))


def help_text():
    print(__doc__)


def main():
    args = sys.argv[1:]
    if not args or args[0] in ("help", "-h", "--help"):
        return help_text()
    cmd, rest = args[0], args[1:]

    if cmd == "state":
        return show(http("GET", "/api/state"), "域状态")
    if cmd == "logs":
        return cmd_logs()
    if cmd == "klist":
        return cmd_klist()
    if cmd == "restart":
        for name in ("tgt", "tgs", "keys.json"):
            try:
                os.remove(cache_path(name))
            except OSError:
                pass
        return show(http("POST", "/api/admin/restart"), "靶场重置")
    if cmd == "reset":
        return show(http("POST", "/api/admin/reset"), "重置 krbtgt 密码一次")
    if cmd == "pac":
        mode = (rest[0] if rest else "").lower()
        if mode not in ("on", "off"):
            print("  [用法] pac on | pac off")
            return
        return show(http("POST", "/api/admin/pac", {"strict": mode == "on"}), "完整 PAC 签名校验")

    if cmd == "login":
        if len(rest) < 2:
            print("  [用法] login alice alice123")
            return
        r = show(http("POST", "/api/as", {"user": rest[0], "password": rest[1]}), "AS-REQ / AS-REP")
        if r.get("ok"):
            save("tgt", r["tgt"])
            print("  TGT 已缓存到 .cache/tgt")
        return

    if cmd == "leak":
        if not rest:
            print("  [用法] leak krbtgt | leak service <spn>")
            return
        if rest[0] == "krbtgt":
            r = show(http("GET", "/api/leak/krbtgt"), "DCSync（模拟）")
            if r.get("ok"):
                keys = load_keys()
                keys["krbtgt"] = r["key"]
                save("keys.json", keys)
                print("  密钥已缓存到 .cache/keys.json，可离线用于 forge golden")
            return
        if rest[0] == "service" and len(rest) > 1:
            r = show(http("GET", "/api/leak/service?spn=" + rest[1]), "本地 SAM 泄露（模拟）")
            if r.get("ok"):
                keys = load_keys()
                keys[rest[1]] = r["key"]
                save("keys.json", keys)
                print("  密钥已缓存到 .cache/keys.json，可离线用于 forge silver")
            return
        print("  [用法] leak krbtgt | leak service <spn>")
        return

    if cmd == "ask":
        tgt = load("tgt")
        if not tgt:
            print("  [拒绝] 缓存里没有 TGT，先 login 或 forge golden")
            return
        if not rest:
            print("  [用法] ask <spn>")
            return
        r = show(http("POST", "/api/tgs", {"tgt": tgt, "spn": rest[0]}),
                 "TGS-REQ / TGS-REP（KDC 签发）")
        if r.get("ok"):
            save("tgs", r["tgs"])
            print("  TGS 已缓存到 .cache/tgs")
            if r.get("forged_tgt"):
                print("  [注意] 这张 TGS 来自伪造的 TGT：DC 有 4769，但找不到对应 4768")
        return

    if cmd == "use":
        tgs = load("tgs")
        if not tgs:
            print("  [拒绝] 缓存里没有 TGS，先 ask 或 forge silver")
            return
        if not rest:
            print("  [用法] use <spn>")
            return
        return show(http("POST", "/api/ap", {"tgs": tgs, "spn": rest[0]}), "AP-REQ（服务端校验）")

    if cmd == "forge":
        return cmd_forge(rest)

    print("  未知命令：%s（用 help 查看全部命令）" % cmd)


if __name__ == "__main__":
    main()
