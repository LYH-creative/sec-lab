"""
server.py - 迷你 AD 域的 KDC + 目标服务 + 状态面板（Python 标准库单文件服务）

一个进程同时扮演三个角色，对应真实拓扑里的三台机器：
  1. 域控的 AS：校验用户口令，签发 TGT，写安全日志 4768；
  2. 域控的 TGS：收 TGT + SPN，签发 TGS，写安全日志 4769；
  3. 成员服务器：用服务账户密钥解开 TGS，校验 PAC 并授权，写本地日志 4624/4625。

关键点：伪造票据由宿主机的 poc/lab.py 离线生成，本服务从不「帮攻击者造假」。
它只做和真实 KDC / 服务端一样的事 —— 拿自己手里的密钥去校验收到的票据。
因此「谁能造出被信任的票据」完全取决于密钥是否泄露，实验结论可直接迁移到
真实 AD 的 impacket ticketer / mimikatz kerberos::golden。

关卡判定完全基于服务端观察到的客观事件（日志、票据指纹、密钥版本），
不依赖客户端上报「我完成了第几关」，避免自欺欺人。
"""

import json
import os
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

import krb

PORT = 8907
FLAG_DIR = "/flags"
HTML_PATH = "/app/index.html"
LEVELS = 6

FLAGS = {}


def load_flags():
    """读取六关的 flag 文本；文件缺失时用占位值，靶场仍可运行。"""
    for n in range(1, LEVELS + 1):
        path = os.path.join(FLAG_DIR, "l%d.flag" % n)
        try:
            with open(path, "r", encoding="utf-8") as f:
                FLAGS[n] = f.read().strip()
        except OSError:
            FLAGS[n] = "FLAG{l%d_missing}" % n


def fresh_state():
    """构造一份干净的域状态。重启容器或调用 /api/admin/restart 都会回到这里。"""
    return {
        "krbtgt_history": [krb.KRBTGT_KEY_V0],
        "resets": 0,
        "pac_strict": False,
        "dc_logs": [],
        "host_logs": [],
        "issued_tgts": set(),
        "issued_tgts_log": [],
        "progress": {n: None for n in range(1, LEVELS + 1)},
        "seen": set(),
        "just_unlocked": [],
    }


STATE = fresh_state()


def now():
    return int(time.time())


def stamp():
    return time.strftime("%H:%M:%S", time.localtime())


def current_krbtgt():
    return STATE["krbtgt_history"][-1]


def log_dc(event, user, spn=None, **extra):
    """写域控安全日志。4768 = 签发 TGT，4769 = 请求服务票据。"""
    row = {"time": stamp(), "event": event, "user": user, "spn": spn or "-"}
    row.update(extra)
    STATE["dc_logs"].append(row)
    if len(STATE["dc_logs"]) > 60:
        STATE["dc_logs"] = STATE["dc_logs"][-60:]


def log_host(event, user, spn, result, **extra):
    """写目标服务器本地日志。4624 = 登录成功，4625 = 登录失败。"""
    row = {"time": stamp(), "event": event, "user": user, "spn": spn, "result": result}
    row.update(extra)
    STATE["host_logs"].append(row)
    if len(STATE["host_logs"]) > 60:
        STATE["host_logs"] = STATE["host_logs"][-60:]


def unlock(level, evidence):
    """解锁关卡。同一个 flag 只发一次，附带可复核的证据说明。"""
    if STATE["progress"][level] is None:
        STATE["progress"][level] = {"evidence": evidence, "time": stamp()}
        STATE["just_unlocked"].append({
            "level": level,
            "flag": FLAGS[level],
            "evidence": evidence,
        })


def read_json(handler):
    """读取并解析请求体 JSON。"""
    try:
        length = int(handler.headers.get("Content-Length", "0"))
        raw = handler.rfile.read(length) if length else b"{}"
        return json.loads(raw.decode())
    except Exception:
        return {}


def send_json(handler, data, status=200):
    """统一 JSON 响应，并把本次请求新解锁的关卡附带返回。"""
    body = dict(data)
    unlocked = STATE["just_unlocked"]
    STATE["just_unlocked"] = []
    if unlocked:
        body["unlocked"] = unlocked
    payload = json.dumps(body, ensure_ascii=False).encode()
    handler.send_response(status)
    handler.send_header("Content-Type", "application/json; charset=utf-8")
    handler.send_header("Content-Length", str(len(payload)))
    handler.end_headers()
    handler.wfile.write(payload)


def api_as(data):
    """AS-REQ / AS-REP：校验口令后签发 TGT，并记录 4768。"""
    user = data.get("user", "")
    password = data.get("password", "")
    record = krb.USERS.get(user)
    if not record or record["password"] is None or record["password"] != password:
        log_dc("4768", user, result="fail", note="口令错误或账户不可交互登录")
        return {"ok": False, "reason": "bad_password"}

    pac = krb.sign_pac(
        krb.pac_body(user, record["sid"], record["groups"], now()),
        current_krbtgt(),
        current_krbtgt(),
    )
    tgt = {
        "type": "TGT",
        "realm": krb.REALM,
        "user": user,
        "sid": record["sid"],
        "groups": record["groups"],
        "pac": pac,
        "issued": now(),
        "lifetime": krb.TEN_HOURS,
    }
    token = krb.seal(tgt, current_krbtgt())
    STATE["issued_tgts"].add(krb.fingerprint(token))
    log_dc("4768", user, result="success", note="AS 签发 TGT（10 小时）")
    return {"ok": True, "tgt": token, "note": "已签发 TGT，客户端解不开，只能原样交回 KDC"}


def api_tgs(data):
    """TGS-REQ / TGS-REP：用 krbtgt 历史密钥校验 TGT，签发 TGS，并记录 4769。

    krbtgt_history 同时保留当前与上一个密钥，对应真实 KDC 的两份密码历史。
    TGT 不是本 KDC 签发过的（黄金票据）只影响日志关联，不影响校验通过 ——
    因为攻击者手里的 krbtgt 密钥本来就是合法的。
    """
    token = data.get("tgt", "")
    spn = data.get("spn", "")
    tgt = krb.unseal(token, STATE["krbtgt_history"])

    if tgt is None or tgt.get("type") != "TGT":
        hint = krb.peek(token) or {}
        if STATE["resets"] >= 2 and hint.get("lifetime", 0) > krb.TEN_HOURS:
            unlock(6, "两次重置 krbtgt 后，旧密钥被挤出历史，10 年期伪造 TGT 校验失败")
        log_dc("4769", hint.get("user", "?"), spn, result="fail", note="TGT 封印校验失败")
        return {"ok": False, "reason": "tgt_invalid"}

    if now() - int(tgt.get("issued", 0)) > int(tgt.get("lifetime", 0)):
        log_dc("4769", tgt.get("user", "?"), spn, result="fail", note="TGT 已过期")
        return {"ok": False, "reason": "tgt_expired"}

    info = krb.service_info(spn)
    if not info:
        return {"ok": False, "reason": "unknown_spn"}
    service_key = krb.spn_key(spn)

    forged_tgt = krb.fingerprint(token) not in STATE["issued_tgts"]
    src_pac = tgt.get("pac", {})
    pac = krb.sign_pac(
        krb.pac_body(
            tgt.get("user", ""),
            tgt.get("sid", ""),
            tgt.get("groups", []),
            src_pac.get("logon_time", now()),
        ),
        current_krbtgt(),
        service_key,
    )
    tgs = {
        "type": "TGS",
        "realm": krb.REALM,
        "spn": spn,
        "user": tgt.get("user", ""),
        "sid": tgt.get("sid", ""),
        "groups": tgt.get("groups", []),
        "pac": pac,
        "issued": now(),
        "lifetime": krb.TEN_HOURS,
    }
    tgs_token = krb.seal(tgs, service_key)
    STATE["issued_tgts"].add(krb.fingerprint(tgs_token))

    note = "TGS-REQ 已处理"
    if forged_tgt:
        note = "KDC 未签发过此 TGT（4768 缺失）；TGT lifetime=%ds，超出 10 小时策略" % int(tgt.get("lifetime", 0))
    log_dc("4769", tgt.get("user", ""), spn, result="success",
           linked_4768=not forged_tgt, note=note)
    return {"ok": True, "tgs": tgs_token, "forged_tgt": forged_tgt}


def api_ap(data):
    """AP-REQ：目标服务器用自己的服务密钥校验 TGS，读取 PAC 决定是否放行。

    服务端默认只校验 svc_sig；pac_strict 打开后还要校验 kdc_sig。
    白银票据持有服务密钥，能过第一关；但签不出 krbtgt 密钥的 KDC 签名，
    所以严格模式一开就露馅。黄金票据经 KDC 重新签 PAC，永远合法。
    """
    token = data.get("tgs", "")
    spn = data.get("spn", "")
    info = krb.service_info(spn)
    if not info:
        return {"ok": False, "reason": "unknown_spn"}
    service_key = krb.spn_key(spn)

    tgs = krb.unseal(token, [service_key])
    if tgs is None or tgs.get("type") != "TGS":
        log_host("4625", "?", spn, "fail", reason="bad_seal")
        return {"ok": False, "reason": "bad_seal"}

    ticket_spn = tgs.get("spn", "")
    user = tgs.get("user", "")
    groups = tgs.get("groups", [])
    pac = tgs.get("pac", {})
    forged = krb.fingerprint(token) not in STATE["issued_tgts"]

    if ticket_spn != spn:
        log_host("4625", user, spn, "fail", reason="spn_mismatch",
                 groups=groups, note="票据 SPN=%s 与请求不符" % ticket_spn)
        if forged:
            unlock(4, "白银票据只能用于签发的那个 SPN，改投其他服务被服务端拒绝")
        return {"ok": False, "reason": "spn_mismatch", "ticket_spn": ticket_spn}

    if now() - int(tgs.get("issued", 0)) > int(tgs.get("lifetime", 0)):
        log_host("4625", user, spn, "fail", reason="expired")
        return {"ok": False, "reason": "expired"}

    if not krb.verify_pac(pac, service_key, "svc_sig"):
        log_host("4625", user, spn, "fail", reason="bad_svc_signature")
        return {"ok": False, "reason": "bad_svc_signature"}

    if STATE["pac_strict"]:
        if not krb.verify_pac(pac, current_krbtgt(), "kdc_sig"):
            log_host("4625", user, spn, "fail", reason="bad_kdc_signature",
                     note="完整 PAC 签名校验：KDC 签名无效")
            if forged:
                STATE["seen"].add("silver_rejected_by_pac")
            return {"ok": False, "reason": "bad_kdc_signature"}

    if info["required_group"] not in groups:
        log_host("4625", user, spn, "fail", reason="access_denied", groups=groups,
                 note="PAC 缺少 %s" % info["required_group"])
        return {"ok": False, "reason": "access_denied"}

    log_host("4624", user, spn, "success", groups=groups,
             forged_tgs=forged, note="服务端用自己的密钥解开了 TGS 并信任 PAC")

    level = None
    if not forged and spn == "http/portal.lab.local":
        unlock(1, "正常三段流程：DC 有 4768 + 4769，目标机有 4624，三方日志能对上")
        level = 1
    elif not forged and spn == "cifs/dc.lab.local" and krb.GROUP_DOMAIN_ADMINS in groups:
        linked = any(r.get("event") == "4769" and r.get("spn") == spn
                     and r.get("linked_4768") is False for r in STATE["dc_logs"])
        if linked:
            unlock(2, "黄金票据：DC 出现 4769 但查不到对应 4768，PAC 里塞进域管组 512")
            level = 2
    elif forged and spn == "cifs/files.lab.local" and not STATE["pac_strict"]:
        unlock(3, "白银票据：目标机 4624 成功，DC 却没有新增任何 4768/4769")
        level = 3

    if STATE["pac_strict"] and not forged and krb.GROUP_DOMAIN_ADMINS in groups:
        STATE["seen"].add("golden_ok_under_pac")
    if "silver_rejected_by_pac" in STATE["seen"] and "golden_ok_under_pac" in STATE["seen"]:
        unlock(5, "完整 PAC 签名强制后：白银票据 KDC 签名验不过被拒，黄金票据经 KDC 重签仍然有效")

    return {
        "ok": True,
        "service": info["desc"],
        "user": user,
        "groups": groups,
        "forged_tgs": forged,
        "level": level,
        "note": "PAC 里写着你是谁、属于哪个组 —— 服务端就照这个放行",
    }


def api_admin_pac(data):
    """靶场控制面板：开关完整 PAC 签名校验（对应 KB5020805 强制模式）。"""
    STATE["pac_strict"] = bool(data.get("strict", False))
    return {"ok": True, "pac_strict": STATE["pac_strict"]}


def api_admin_reset():
    """靶场控制面板：重置 krbtgt 密码一次。KDC 仍保留上一个密钥。"""
    STATE["krbtgt_history"].append(krb.new_krbtgt_key())
    STATE["krbtgt_history"] = STATE["krbtgt_history"][-2:]
    STATE["resets"] += 1
    log_dc("4738", "krbtgt", result="success",
           note="krbtgt 密码已重置 %d 次；KDC 当前接受 %d 把历史密钥" %
                (STATE["resets"], len(STATE["krbtgt_history"])))
    return {
        "ok": True,
        "resets": STATE["resets"],
        "accepted_keys": len(STATE["krbtgt_history"]),
        "note": "一次重置不够：旧密钥仍在历史里，伪造 TGT 依然有效",
    }


def api_admin_restart():
    """靶场控制面板：清空所有日志与进度，回到初始状态。"""
    global STATE
    STATE = fresh_state()
    return {"ok": True, "note": "靶场已重置"}


def api_state():
    """给 Web 面板和 CLI 用的只读状态快照。"""
    return {
        "ok": True,
        "realm": krb.REALM,
        "domain_sid": krb.DOMAIN_SID,
        "resets": STATE["resets"],
        "accepted_keys": len(STATE["krbtgt_history"]),
        "pac_strict": STATE["pac_strict"],
        "dc_logs": list(STATE["dc_logs"]),
        "host_logs": list(STATE["host_logs"]),
        "progress": {
            str(k): (dict(v, flag=FLAGS[k]) if v else None)
            for k, v in STATE["progress"].items()
        },
        "services": {spn: v["desc"] for spn, v in krb.SERVICES.items()},
        "total_levels": LEVELS,
    }


class Handler(BaseHTTPRequestHandler):
    """极简路由：静态面板 + 一组 JSON API，全部走标准库。"""

    def log_message(self, fmt, *args):
        pass

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path
        query = parse_qs(parsed.query)

        if path == "/":
            try:
                with open(HTML_PATH, "r", encoding="utf-8") as f:
                    html = f.read().encode()
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(html)))
                self.end_headers()
                self.wfile.write(html)
            except OSError:
                send_json(self, {"ok": False, "reason": "panel_missing"}, 500)
            return

        if path == "/api/state":
            return send_json(self, api_state())

        if path == "/api/leak/krbtgt":
            return send_json(self, {
                "ok": True,
                "spn": "krbtgt/%s" % krb.REALM,
                "key": current_krbtgt(),
                "source": "DCSync / ntds.dit（模拟）",
                "note": "拿到它等于能签发任意 TGT —— 这是黄金票据的前提",
            })

        if path == "/api/leak/service":
            spn = (query.get("spn") or [""])[0]
            key = krb.spn_key(spn)
            if not key:
                return send_json(self, {"ok": False, "reason": "unknown_spn"}, 404)
            return send_json(self, {
                "ok": True,
                "spn": spn,
                "key": key,
                "source": "目标机本地 SAM / 机器账户（模拟）",
                "note": "只够伪造这一个 SPN 的 TGS —— 这是白银票据的前提",
            })

        return send_json(self, {"ok": False, "reason": "not_found"}, 404)

    def do_POST(self):
        path = urlparse(self.path).path
        data = read_json(self)

        if path == "/api/as":
            return send_json(self, api_as(data))
        if path == "/api/tgs":
            return send_json(self, api_tgs(data))
        if path == "/api/ap":
            return send_json(self, api_ap(data))
        if path == "/api/admin/pac":
            return send_json(self, api_admin_pac(data))
        if path == "/api/admin/reset":
            return send_json(self, api_admin_reset())
        if path == "/api/admin/restart":
            return send_json(self, api_admin_restart())

        return send_json(self, {"ok": False, "reason": "not_found"}, 404)


def main():
    load_flags()
    server = ThreadingHTTPServer(("0.0.0.0", PORT), Handler)
    print("kerberos lab listening on 0.0.0.0:%d" % PORT, flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
