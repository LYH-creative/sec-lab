#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
server.py —— replay / AD CS 协议级练习靶场（单进程，纯标准库）

模拟的世界里有四个角色，都跑在同一个 HTTP 服务里，用路径区分：

  /bank/*      业务应用（转账接口）          —— L1 / L2 / 修复对照
  /ntlm/*      NTLM 认证入口                —— L3
  /victim/*    被强制发起认证的 DC 机器账户  —— L4 的「认证 oracle」
  /certsrv/*   AD CS Web 注册（ESC8 目标）   —— L4 / L5
  /kdc/*       模拟 PKINIT 换 TGT            —— L5
  /admin       域管才能看的页面              —— L5 终点

必须说清楚的边界（不要把这个当成真域环境）：
  * 没有 Windows 域、没有 LDAP、没有 RPC、没有真 X.509 / Kerberos。
  * 证书是 JSON + HMAC，代替「CA 私钥签的 X.509」；TGT 同理。
    这两处 HMAC 只是为了演示「信任链」：KDC 信 CA 签的身份映射。
  * NTLM 报文是真实结构，NTLMv2 响应是真算的，challenge 是真随机的。
    所以「不需要密码、只搬字节也能通过验签」这件事是真的，不是演员。
  * 真机里 NTLM over HTTP 绑定在同一条 TCP 连接上，这里用
    X-NTLM-Challenge 头显式关联，方便拆包观察，语义等价。

对应真机攻击链：
  PetitPotam / PrinterBug 强制 DC 认证
    → ntlmrelayx 把 NetNTLMv2 中继到 http://CA/certsrv/certfnsh.asp (ESC8)
    → 用可指定 SAN 的模板申请域管证书 (ESC1)
    → Rubeus asktgt /certificate /ptt 做 PKINIT 换 TGT
    → DCSync
"""

import base64
import hashlib
import hmac
import json
import os
import secrets
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

import ntlm

PORT = int(os.environ.get("LAB_PORT", "8080"))
FLAG_DIR = os.environ.get("LAB_FLAG_DIR") or os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "flags"
)

# 三个「密钥」。真机里分别对应：应用签名密钥、企业 CA 私钥、krbtgt 密钥。
# 教学环境写死在源码里，是为了让你能对照签名覆盖字段，不是让你练代码审计。
BANK_KEY = b"seclab-bank-hmac-key-2026"
CA_KEY = b"seclab-enterprise-ca-private-key"
KDC_KEY = b"seclab-krbtgt-key"

CA_NAME = "CN=lab-ADCS-CA,DC=lab,DC=local"
REALM = "LAB.LOCAL"

# 「目录」里只存 NT hash，跟真实 DC 的 NTDS.dit 一样。
# DC$ 的密码只在这里出现，victim oracle 绝不把它交给攻击者。
DIRECTORY = {
    "LAB\\alice": ntlm.nt_hash("Passw0rd!"),
    "LAB\\DC$": ntlm.nt_hash("MachineAcc0nt!"),
}

# 证书模板。VulnWebServer 复刻了 ESC1 + ESC8 需要的四个错误配置：
#   1. ENROLLEE_SUPPLIES_SUBJECT（注册者可自己填 subject / SAN）
#   2. EKU 含 Client Authentication（能拿去 PKINIT）
#   3. 不需要管理员审批（PEND_ALL_REQUESTS 没开）
#   4. Domain Computers 可注册（DC$ 属于这一类）
TEMPLATES = {
    "VulnWebServer": {
        "display_name": "Vulnerable Web Server",
        "enrollee_supplies_subject": True,
        "eku": ["clientAuth", "serverAuth"],
        "manager_approval": False,
        "enroll_acl": ["Domain Computers", "Domain Controllers", "Domain Users"],
        "validity_days": 365,
    },
    "User": {
        "display_name": "User (baseline, safe)",
        "enrollee_supplies_subject": False,
        "eku": ["clientAuth"],
        "manager_approval": True,
        "enroll_acl": ["Domain Users"],
        "validity_days": 365,
    },
}

STATE = {
    "l1": {"balance": 100, "received": 0, "count": 0},
    "l2": {"balance": 100, "received": 0, "count": 0, "nonces": set()},
    "safe": {"balance": 100, "nonces": set()},
    "l3": {},                 # sid -> {challenge, target_info}
    "victim": {},             # vid -> {type1}
    "ca_pending": {},         # cid -> {challenge, target_info}
    "ca_sessions": {},        # token -> {user, domain}
    "certs": {},              # serial -> cert dict
    "tgt_serials": set(),
}
LOCK = threading.Lock()

TARGET_GOAL = 50   # 重放 5 次 × 10 块


# ---------------------------------------------------------------------------
#  通用小工具
# ---------------------------------------------------------------------------

def read_flag(level):
    path = os.path.join(FLAG_DIR, "l%d.flag" % level)
    with open(path, "r", encoding="utf-8") as fp:
        return fp.read().strip()


def canonical(obj):
    """签名前的规范化序列化：键排序、无多余空格，保证两端算出来一致。"""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False).encode("utf-8")


def hmac_hex(key, raw, algo=hashlib.md5):
    return hmac.new(key, raw, algo).hexdigest()


def b64e(raw):
    return base64.b64encode(raw).decode("ascii")


def b64d(text):
    return base64.b64decode(text)


def sign_bank_weak(body):
    """故意的错：签名只覆盖业务字段，nonce / ts 都能随便改。"""
    raw = "%s|%s|%s" % (body.get("from", ""), body.get("to", ""),
                        body.get("amount", ""))
    return hmac_hex(BANK_KEY, raw.encode())


def sign_bank_safe(body):
    """正确做法：所有参与语义的字段都得进签名。"""
    raw = "%s|%s|%s|%s|%s" % (
        body.get("from", ""), body.get("to", ""), body.get("amount", ""),
        body.get("nonce", ""), body.get("ts", ""),
    )
    return hmac_hex(BANK_KEY, raw.encode())


def bank_safe_validate(payload):
    """
    加固版转账的三道检查，并且真的消费 nonce。
    抽成模块级函数是为了让 /bank/safe/transfer 和 /safe/check 走同一份代码 ——
    修复对照里的结论必须是实跑出来的，不能是写在文档里的"应该会被挡"。
    """
    blocked = []
    if not hmac.compare_digest(str(payload.get("sig", "")), sign_bank_safe(payload)):
        blocked.append("签名校验失败（nonce / ts 也在签名里，改一个字节就废）")
    try:
        ts = int(payload.get("ts", 0))
        if abs(int(time.time()) - ts) > 60:
            blocked.append("时间戳超出 60 秒窗口")
    except (TypeError, ValueError):
        blocked.append("时间戳格式不对")
    nonce = str(payload.get("nonce", ""))
    if not nonce:
        blocked.append("缺少 nonce")
    if blocked:
        return blocked
    with LOCK:
        if nonce in STATE["safe"]["nonces"]:
            return ["nonce 已使用（一次性）"]
        STATE["safe"]["nonces"].add(nonce)
        STATE["safe"]["balance"] -= 10
    return []


def make_sample(level):
    body = {"from": "alice", "to": "shop", "amount": 10}
    if level == 2:
        body["nonce"] = secrets.token_hex(8)
        body["ts"] = int(time.time())
    body["sig"] = sign_bank_weak(body)
    return body


def issue_certificate(session, template_name, subject, san):
    """签发「证书」。真机里这一步是 CA 用私钥签一张 X.509，这里用 HMAC 代替。"""
    template = TEMPLATES.get(template_name)
    if not template:
        return None, "未知模板 %s" % template_name
    if not template["enrollee_supplies_subject"]:
        return None, "模板不允许注册者提供 subject/SAN（ENROLLEE_SUPPLIES_SUBJECT 未开启）"
    if template["manager_approval"]:
        return None, "模板要求管理员审批，请求被挂起"
    if "clientAuth" not in template["eku"]:
        return None, "模板 EKU 不含 Client Authentication，证书不能用于 PKINIT"
    if not session.get("is_machine") and "Domain Users" not in template["enroll_acl"]:
        return None, "请求者无注册权限"

    now = int(time.time())
    cert = {
        "serial": secrets.token_hex(8).upper(),
        "issuer": CA_NAME,
        "template": template_name,
        "subject": subject,
        "san": san,
        "eku": template["eku"],
        "requested_by": session["domain"] + "\\" + session["user"],
        "not_before": now,
        "not_after": now + template["validity_days"] * 86400,
    }
    cert["ca_sig"] = hmac_hex(CA_KEY, canonical(cert), hashlib.sha256)
    return cert, None


def verify_ca_signature(cert):
    sig = cert.get("ca_sig", "")
    unsigned = {k: v for k, v in cert.items() if k != "ca_sig"}
    return hmac.compare_digest(sig, hmac_hex(CA_KEY, canonical(unsigned), hashlib.sha256))


def make_tgt(identity, groups):
    now = int(time.time())
    tgt = {
        "user": identity,
        "realm": REALM,
        "groups": groups,
        "issued": now,
        "expires": now + 36000,
        "type": "TGT(PKINIT)",
    }
    tgt["kdc_sig"] = hmac_hex(KDC_KEY, canonical(tgt), hashlib.sha256)
    return tgt


def verify_tgt(tgt):
    sig = tgt.get("kdc_sig", "")
    unsigned = {k: v for k, v in tgt.items() if k != "kdc_sig"}
    if not hmac.compare_digest(sig, hmac_hex(KDC_KEY, canonical(unsigned), hashlib.sha256)):
        return False
    return time.time() <= tgt.get("expires", 0)


# ---------------------------------------------------------------------------
#  HTML 页面。首页要把「做什么 / 对应真机哪一步」写清楚，卡住时不用翻源码。
# ---------------------------------------------------------------------------

PAGE_CSS = """
:root{--bg:#0a0e14;--panel:#121a24;--line:#223040;--text:#dbe6f2;
--dim:#7c8fa3;--mute:#52616f;--accent:#2ee6a8;--warn:#ffb545;
--mono:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace}
*{box-sizing:border-box}body{margin:0;padding:40px 20px 80px;background:var(--bg);
color:var(--text);font:15px/1.75 -apple-system,BlinkMacSystemFont,"PingFang SC","Microsoft YaHei",sans-serif}
.wrap{max-width:980px;margin:0 auto}h1{font-size:28px;margin:0 0 6px}
h1 .p{color:var(--accent);font-family:var(--mono)}h2{font-size:18px;margin:38px 0 14px;
padding-bottom:8px;border-bottom:1px solid var(--line)}
.lede{color:var(--dim);max-width:760px}code{font-family:var(--mono);font-size:13px;
color:var(--accent);background:rgba(46,230,168,.08);padding:2px 6px;border-radius:4px}
pre{background:#0c1219;border:1px solid var(--line);border-radius:8px;padding:14px 16px;
overflow-x:auto;font-family:var(--mono);font-size:12.5px;line-height:1.7;color:#b9cede}
table{width:100%;border-collapse:collapse;font-size:13.5px}th,td{text-align:left;
padding:9px 10px;border-bottom:1px solid var(--line);vertical-align:top}
th{color:var(--mute);font-weight:600;font-size:12px;letter-spacing:.05em}
td code{white-space:nowrap}.card{background:var(--panel);border:1px solid var(--line);
border-radius:10px;padding:16px 18px;margin:12px 0}.card h3{margin:0 0 6px;font-size:15px}
.card p{margin:4px 0;color:var(--dim);font-size:13.5px}
.note{background:rgba(255,181,69,.05);border-left:2px solid var(--warn);
padding:14px 18px;border-radius:0 8px 8px 0;color:var(--dim);font-size:13.5px}
a{color:var(--accent)}ul{color:var(--dim);font-size:13.5px;padding-left:22px}
li{margin:5px 0}
"""


def page_home():
    return """<!DOCTYPE html><html lang="zh-CN"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>SecLab · Replay / AD CS</title><style>__CSS__</style></head><body><div class="wrap">
<h1><span class="p">&gt;_</span> Replay &amp; AD CS</h1>
<p class="lede">五关一条链：先打穿业务接口的防重放，再理解 NTLM 挑战响应，
最后把 DC 的认证字节中继到 AD CS Web 注册接口，申请域管证书、换 TGT、拿到域管页面。
<b>纯 Python 标准库模拟，不是 Windows 域</b>，但 NTLMv2 的报文和验签是真算的。</p>

<h2>关卡</h2>
<div class="card"><h3>L1 · 请求重放（无防护）</h3>
<p><code>GET /bank/sample?level=1</code> 拿一条合法转账请求，原样 POST 到
<code>/bank/l1/transfer</code> 五次。不用破解签名 —— 这就是重放攻击的重点。</p></div>
<div class="card"><h3>L2 · 假 nonce（签名没覆盖）</h3>
<p><code>GET /bank/sample?level=2</code> 的报文带了 <code>nonce</code> 和 <code>ts</code>，
服务端也真的去重了。但签名只覆盖 <code>from|to|amount</code>，改 nonce 不用重算签名。目标仍是
<code>/bank/l2/transfer</code> 五次。</p></div>
<div class="card"><h3>L3 · 自己算一次 NTLMv2</h3>
<p>账号 <code>LAB\\alice / Passw0rd!</code>。POST Type1 到 <code>/ntlm/l3/type1</code> 拿
Type2（内含 8 字节 challenge），用 MD4 + HMAC-MD5 算 Type3 提交到
<code>/ntlm/l3/type3</code>。<code>ntlm.py</code> 已经实现好了，可以直接 import。</p></div>
<div class="card"><h3>L4 · ESC8：只搬字节的中继</h3>
<p>四步：<code>POST /victim/negotiate</code> 拿 victim 的 Type1 → 转发给
<code>/certsrv/certfnsh.asp</code> 换 Type2 → 把 Type2 交给
<code>/victim/authenticate</code> 换 Type3 → 把 Type3 转发回 CA。<b>全程没有密码、没有 hash</b>，
CA 看到的身份是 <code>LAB\\DC$</code>。认证成功即出 flag。</p></div>
<div class="card"><h3>L5 · ESC1 + PKINIT</h3>
<p><code>GET /certsrv/templates</code> 看模板配置。带 <code>X-CA-Session</code> 向
<code>/certsrv/certfnsh.asp</code> 提交 <code>VulnWebServer</code> 模板请求，
SAN 填 <code>upn=administrator@lab.local</code>；拿证书 POST 到 <code>/kdc/asktgt</code> 换 TGT，
最后带 <code>X-TGT</code> 访问 <code>/admin</code>。</p></div>

<h2>真机对照（这部分不是模拟出来的）</h2>
<table><tr><th>本靶场</th><th>真实 AD 环境</th></tr>
<tr><td><code>/victim/negotiate</code></td><td>PetitPotam (MS-EFSR) / PrinterBug (MS-RPRN) 强制 DC 发起认证</td></tr>
<tr><td>转发 Type1/2/3</td><td><code>ntlmrelayx.py -t http://ca/certsrv/certfnsh.asp --adcs --template DomainController</code></td></tr>
<tr><td><code>/certsrv/certfnsh.asp</code></td><td>AD CS Web Enrollment 角色，ESC8（HTTP 未启用 EPA、未禁用 NTLM）</td></tr>
<tr><td>VulnWebServer 模板</td><td>ESC1：<code>msPKI-Certificate-Name-Flag</code> 带 ENROLLEE_SUPPLIES_SUBJECT</td></tr>
<tr><td><code>/kdc/asktgt</code> + HMAC 证书</td><td><code>Rubeus asktgt /user:dc$ /certificate:x.pfx /ptt</code>（PKINIT）</td></tr>
<tr><td><code>/admin</code> + TGT</td><td>Pass-the-Ticket 后 DCSync 拿 krbtgt / Administrator hash</td></tr>
</table>

<h2>修复对照</h2>
<p><a href="/safe">/safe</a> 逐条演示：<code>/bank/safe/transfer</code> 的全字段签名 + nonce 一次性 + 窄时间窗，
EPA 通道绑定挡 relay，模板关闭 ENROLLEE_SUPPLIES_SUBJECT + 强证书映射（KB5014754）挡 ESC1。
<a href="/safe/check">/safe/check</a> 直接返回各项拦截结果。</p>

<div class="note"><b>边界：</b>本机 Docker 是 Linux/aarch64，跑不了 Windows 容器；
真·AD CS 需要 Windows Server + AD DS + 企业 CA。这里用的是协议级模拟：
证书和 TGT 是 JSON + HMAC（代替 CA 私钥签的 X.509 / krbtgt 签的 PAC），
没有 LDAP、RPC、Kerberos 实现。NTLM 部分是真的。</div>

<h2>一键验证</h2>
<pre>python3 poc/exp.py              # 五关全跑
python3 poc/exp.py --only L4     # 只跑中继那一关
python3 ntlm.py                  # 协议层自测（MD4 向量 + Type1/2/3 往返）</pre>
</div></body></html>""".replace("__CSS__", PAGE_CSS)


def page_safe():
    return """<!DOCTYPE html><html lang="zh-CN"><head><meta charset="utf-8">
<title>修复对照 · Replay / AD CS</title><style>__CSS__</style></head><body><div class="wrap">
<h1><span class="p">&gt;_</span> 修复对照</h1>
<p class="lede">同一批攻击，换到加固后的实现上会死在哪一步。
点 <a href="/safe/check">/safe/check</a> 看每条的实际返回：
前五项是<b>真的调用加固代码跑出来的</b>，后两项（TLS / LDAP 相关加固）
本模拟靶场没有对应实现，只列真机清单，不当实测结果看。</p>

<h2>1 · 防重放的三要素，缺一不可</h2>
<ul>
<li><b>签名覆盖全部字段</b> —— 只签业务字段，nonce 就是个摆设（L2 的洞）。</li>
<li><b>nonce 一次性</b> —— 服务端必须真的记住用过的 nonce，校验和记账要在同一个临界区。</li>
<li><b>时间窗要窄</b> —— 否则报文能被囤几天再重放。60 秒窗口 + nonce 集合才够。</li>
</ul>
<p><code>POST /bank/safe/transfer</code> 同时做了三件事，签名是
<code>HMAC(from|to|amount|nonce|ts)</code>。</p>

<h2>2 · 挡 NTLM relay（ESC8 的根治）</h2>
<ul>
<li>CA 上<b>禁用 Web Enrollment 的 NTLM</b>，或改用 CES/CEP + HTTPS +
<b>Extended Protection for Authentication（EPA / 通道绑定）</b>：
把 TLS 通道绑定哈希塞进 NTLM 的 AV pair，中继者转发时会校验失败。</li>
<li>全域网开 <b>SMB signing</b> / LDAP signing + channel binding，堵住 SMB/LDAP 中继面。</li>
<li>打 <b>CVE-2021-36942 (PetitPotam)</b> 补丁，关掉不必要的 EFSRPC 暴露面。</li>
<li>challenge 一次性 + 绑定连接：本靶场 L3 的 challenge 用后即删，重复提交 Type3 直接失败。</li>
</ul>

<h2>3 · 挡 ESC1 / 证书提权</h2>
<ul>
<li>模板关掉 <b>ENROLLEE_SUPPLIES_SUBJECT</b>，SAN 由目录里的属性自动生成。</li>
<li>开 <b>manager approval</b>、收窄 <b>Enroll ACL</b>（别给 Domain Computers / Everyone）。</li>
<li>打 <b>KB5014754</b> 并切到 <b>强证书映射</b>（证书里带 SID 扩展），
2022 年之前那种「只靠 UPN/DNS 字符串映射」会被拒 —— <code>/kdc/safe/asktgt</code> 演示了这条。</li>
<li>定期用 <code>certipy find -vulnerable</code> / <code>Certify.exe /find /vulnerable</code> 扫模板。</li>
</ul>

<div class="note">真机排查顺序一般是：先找可利用模板（ESC1~ESC13），
再找可中继的注册端点（ESC8），最后看 CA 自身的 ACL（ESC7）和
KDC 的证书映射强度。<a href="/">← 回首页</a></div>
</div></body></html>""".replace("__CSS__", PAGE_CSS)


# ---------------------------------------------------------------------------
#  HTTP 处理
# ---------------------------------------------------------------------------

class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "SecLab-ReplayADCS/1.0"

    def log_message(self, fmt, *args):
        # 默认打到 stderr 的日志里能看到每一次 401 / 重放，方便对着看时序
        print("[%s] %s" % (self.log_date_time_string(), fmt % args), flush=True)

    def _send(self, status, body, content_type="application/json; charset=utf-8",
              extra=None):
        if isinstance(body, (dict, list)):
            body = json.dumps(body, ensure_ascii=False, indent=2).encode("utf-8")
        elif isinstance(body, str):
            body = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        for key, value in (extra or {}).items():
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(body)

    def _json(self, obj, status=200, extra=None):
        self._send(status, obj, extra=extra)

    def _fail(self, message, status=400):
        self._json({"ok": False, "error": message}, status)

    def _body(self):
        length = int(self.headers.get("Content-Length", "0") or "0")
        raw = self.rfile.read(length) if length else b"{}"
        try:
            return json.loads(raw.decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            return {}

    def do_GET(self):
        parsed = urlparse(self.path)
        path, query = parsed.path, parse_qs(parsed.query)

        if path == "/":
            return self._send(200, page_home(), "text/html; charset=utf-8")
        if path == "/safe":
            return self._send(200, page_safe(), "text/html; charset=utf-8")
        if path == "/safe/check":
            return self._json(safe_checks())
        if path == "/bank/sample":
            level = int(query.get("level", ["1"])[0])
            if level not in (1, 2):
                return self._fail("level 只能是 1 或 2")
            return self._json({
                "endpoint": "/bank/l%d/transfer" % level,
                "method": "POST",
                "body": make_sample(level),
                "note": "这是一条抓到的合法请求，签名已经算好，直接重放即可。",
            })
        if path == "/bank/state":
            with LOCK:
                return self._json({
                    "l1": {k: v for k, v in STATE["l1"].items()},
                    "l2": {k: v for k, v in STATE["l2"].items() if k != "nonces"},
                    "l2_nonces_seen": len(STATE["l2"]["nonces"]),
                    "goal": TARGET_GOAL,
                })
        if path == "/ntlm/l3":
            return self._json({
                "user": "alice", "domain": "LAB", "password": "Passw0rd!",
                "step1": "POST /ntlm/l3/type1  {\"type1\": \"<base64>\"}",
                "step2": "用 ntlm.make_type3_from_type2(ntlm.nt_hash(password), user, domain, type2) 造 Type3",
                "step3": "POST /ntlm/l3/type3  {\"sid\": \"...\", \"type3\": \"<base64>\"}",
                "note": "challenge 用后即删，同一个 Type3 交第二次会被拒。",
            })
        if path == "/certsrv/templates":
            return self._json({
                "ca": CA_NAME,
                "templates": TEMPLATES,
                "hint": "找那个 enrollee_supplies_subject=true、eku 含 clientAuth、又不需要审批的模板。",
            })
        if path == "/state":
            with LOCK:
                return self._json({
                    "ca_pending": len(STATE["ca_pending"]),
                    "ca_sessions": list(STATE["ca_sessions"].keys()),
                    "certs_issued": len(STATE["certs"]),
                })
        if path == "/admin":
            return self._handle_admin()
        return self._fail("未知路径 %s（看 / 上的关卡说明）" % path, 404)

    def do_POST(self):
        path = urlparse(self.path).path
        body = self._body()

        if path == "/bank/l1/transfer":
            return self._bank_transfer(1, body)
        if path == "/bank/l2/transfer":
            return self._bank_transfer(2, body)
        if path == "/bank/safe/transfer":
            return self._bank_safe(body)
        if path == "/ntlm/l3/type1":
            return self._l3_type1(body)
        if path == "/ntlm/l3/type3":
            return self._l3_type3(body)
        if path == "/victim/negotiate":
            return self._victim_negotiate()
        if path == "/victim/authenticate":
            return self._victim_authenticate(body)
        if path == "/certsrv/certfnsh.asp":
            # body 已经在 do_POST 开头读过一次了，这里传下去，不能重复读 rfile
            return self._certsrv(body)
        if path == "/kdc/asktgt":
            return self._asktgt(body, safe=False)
        if path == "/kdc/safe/asktgt":
            return self._asktgt(body, safe=True)
        return self._fail("未知路径 %s" % path, 404)

    # ---------------- L1 / L2：业务接口的重放 ----------------

    def _bank_transfer(self, level, body):
        """共同点：签名只覆盖业务字段。L1 连 nonce 都没有，L2 有 nonce 但不进签名。"""
        if not hmac.compare_digest(str(body.get("sig", "")), sign_bank_weak(body)):
            return self._fail("签名校验失败", 403)
        if body.get("from") != "alice" or body.get("to") != "shop" or body.get("amount") != 10:
            return self._fail("只支持 alice -> shop 转账 10")

        if level == 2:
            try:
                ts = int(body.get("ts", 0))
            except (TypeError, ValueError):
                return self._fail("时间戳格式不对")
            if abs(int(time.time()) - ts) > 300:
                return self._fail("时间戳超出 300 秒窗口", 403)
            nonce = str(body.get("nonce", ""))
            if not nonce:
                return self._fail("缺少 nonce")
            with LOCK:
                if nonce in STATE["l2"]["nonces"]:
                    return self._fail("nonce 已经用过（服务端去重生效了，但签名没覆盖它）", 409)
                STATE["l2"]["nonces"].add(nonce)

        with LOCK:
            book = STATE["l%d" % level]
            book["balance"] -= 10
            book["received"] += 10
            book["count"] += 1
            done = book["received"] >= TARGET_GOAL
            snapshot = {"balance": book["balance"], "received": book["received"],
                        "count": book["count"]}

        result = {"ok": True, "level": level, **snapshot,
                  "note": "服务端没有校验这条请求是不是新的。"}
        if level == 2:
            result["note"] = "nonce 被去重了，但换一个 nonce 就能再来一次 —— 因为它不在签名里。"
        if done:
            result["flag"] = read_flag(level)
            result["note"] = "累计 %d，拿 flag。" % TARGET_GOAL
        return self._json(result)

    def _bank_safe(self, body):
        """加固版：全字段签名 + nonce 一次性 + 60 秒窗口，改动任一处都会被拒。"""
        blocked = bank_safe_validate(body)
        if blocked:
            return self._json({"ok": False, "blocked_by": blocked}, 403)
        return self._json({"ok": True, "balance": STATE["safe"]["balance"],
                           "note": "这条请求只会被记一次账。"})

    # ---------------- L3：自己算一次 NTLMv2 ----------------

    def _l3_type1(self, body):
        try:
            info = ntlm.parse_type1(b64d(body.get("type1", "")))
        except Exception as exc:
            return self._fail("Type1 解析失败：%s" % exc)
        challenge = secrets.token_bytes(8)
        target_info = ntlm.build_target_info()
        sid = secrets.token_hex(8)
        with LOCK:
            STATE["l3"][sid] = {"challenge": challenge, "target_info": target_info}
        type2 = ntlm.build_type2(challenge, target_info, "LAB")
        return self._json({
            "sid": sid,
            "type2": b64e(type2),
            "challenge_hex": challenge.hex(),
            "target_name": "LAB",
            "parsed_type1": info,
            "note": "8 字节 challenge 是服务端现给的，客户端拿它和密码派生值算 HMAC。",
        }, extra={"WWW-Authenticate": "NTLM " + b64e(type2)})

    def _l3_type3(self, body):
        sid = body.get("sid", "")
        with LOCK:
            pending = STATE["l3"].pop(sid, None)
        if not pending:
            return self._fail("sid 无效或 challenge 已使用（一次性的，防重放）", 401)
        try:
            parsed = ntlm.parse_type3(b64d(body.get("type3", "")))
        except Exception as exc:
            return self._fail("Type3 解析失败：%s" % exc)
        if parsed["user"].lower() != "alice":
            return self._fail("身份不对：期望 LAB\\alice，收到 %s" % parsed["user"], 403)
        ok = ntlm.verify_ntlmv2_response(
            DIRECTORY["LAB\\alice"], "alice", "LAB",
            pending["challenge"], parsed["nt_response"]
        )
        if not ok:
            return self._fail("NTLMv2 响应验签失败（密码算错了？）", 403)
        return self._json({
            "ok": True, "authenticated_as": "LAB\\alice",
            "nt_response_len": len(parsed["nt_response"]),
            "flag": read_flag(3),
            "note": "验签只用到 NT hash + challenge + Type3 里的响应，不需要明文密码 —— 这正是 relay 能成立的原因。",
        })

    # ---------------- L4：victim oracle —— 只吐字节，不吐密钥 ----------------

    def _victim_negotiate(self):
        """模拟 PetitPotam 之后 DC 主动向攻击者发起的那一次 NTLM 协商。"""
        type1 = ntlm.build_type1("LAB", "DC")
        vid = secrets.token_hex(8)
        with LOCK:
            STATE["victim"][vid] = {"type1": type1}
        return self._json({
            "vid": vid,
            "type1": b64e(type1),
            "identity": "LAB\\DC$（机器账户，真机里由 PetitPotam / PrinterBug 强制触发）",
            "note": "你拿到的是 Type1 字节。密码和 NT hash 都不会给你。",
        })

    def _victim_authenticate(self, body):
        """DC 收到 Type2 后自己算 Type3 并交出来。攻击者全程只搬运。"""
        vid = body.get("vid", "")
        with LOCK:
            pending = STATE["victim"].get(vid)
        if not pending:
            return self._fail("vid 无效", 400)
        try:
            type2 = b64d(body.get("type2", ""))
            ntlm.parse_type2(type2)
        except Exception as exc:
            return self._fail("Type2 解析失败：%s" % exc)
        # 注意这一行：DC$ 的 NT hash 只在服务端内部出现，绝不下发给攻击者。
        type3 = ntlm.make_type3_from_type2(
            DIRECTORY["LAB\\DC$"], "DC$", "LAB", type2, "DC"
        )
        return self._json({
            "type3": b64e(type3),
            "note": "victim 用自己的机器账户密钥算好了 Type3。你只拿到了字节。",
        })

    # ---------------- L4 / L5：certsrv（ESC8 中继目标 + ESC1 注册） ----------------

    def _certsrv(self, body):
        auth = self.headers.get("Authorization", "")
        if auth.lower().startswith("ntlm "):
            return self._certsrv_ntlm(b64d(auth.split(None, 1)[1].strip()))

        token = self.headers.get("X-CA-Session", "")
        with LOCK:
            session = STATE["ca_sessions"].get(token)
        if not session:
            return self._json({
                "ok": False,
                "error": "需要 NTLM 认证或有效的 X-CA-Session",
                "hint": "ESC8：CA 的 Web 注册端点接受 NTLM，且没开 EPA / 通道绑定。",
            }, 401, {"WWW-Authenticate": "NTLM"})

        template = body.get("template", "")
        subject = body.get("subject", "CN=dc$")
        san = body.get("san", "")
        cert, err = issue_certificate(session, template, subject, san)
        if err:
            return self._json({"ok": False, "error": err}, 403)
        with LOCK:
            STATE["certs"][cert["serial"]] = cert
        return self._json({
            "ok": True,
            "cert": b64e(canonical(cert)),
            "cert_view": cert,
            "note": "ESC1：注册者自己提供 SAN，CA 照抄进证书。下一步拿它去做 PKINIT。",
        })

    def _certsrv_ntlm(self, msg):
        # 只看消息类型字段就能判断这一步是 Type1 还是 Type3
        header_type = int.from_bytes(msg[8:12], "little") if len(msg) >= 12 else 0

        if header_type == 1:
            ntlm.parse_type1(msg)
            challenge = secrets.token_bytes(8)
            target_info = ntlm.build_target_info(dns_computer="adcs.lab.local")
            cid = secrets.token_hex(8)
            with LOCK:
                STATE["ca_pending"][cid] = {
                    "challenge": challenge, "target_info": target_info,
                }
            type2 = ntlm.build_type2(challenge, target_info, "LAB")
            return self._json({
                "stage": "type2", "cid": cid,
                "challenge_hex": challenge.hex(),
                "type2": b64e(type2),
                "note": "CA 把随机 challenge 发给「客户端」。中继者要原样搬给 victim。",
            }, 401, {
                "WWW-Authenticate": "NTLM " + b64e(type2),
                "X-NTLM-Challenge": cid,
            })

        if header_type == 3:
            cid = self.headers.get("X-NTLM-Challenge", "")
            with LOCK:
                pending = STATE["ca_pending"].pop(cid, None)
            if not pending:
                return self._fail("X-NTLM-Challenge 无效或已使用", 401)
            try:
                parsed = ntlm.parse_type3(msg)
            except Exception as exc:
                return self._fail("Type3 解析失败：%s" % exc)
            identity = parsed["domain"] + "\\" + parsed["user"]
            key = DIRECTORY.get(identity)
            if key is None:
                return self._fail("目录里没有这个账户：%s" % identity, 403)
            ok = ntlm.verify_ntlmv2_response(
                key, parsed["user"], parsed["domain"],
                pending["challenge"], parsed["nt_response"]
            )
            if not ok:
                return self._fail("NTLMv2 验签失败（challenge 和响应对不上）", 403)
            token = secrets.token_hex(16)
            with LOCK:
                STATE["ca_sessions"][token] = {
                    "user": parsed["user"], "domain": parsed["domain"],
                    "is_machine": parsed["user"].endswith("$"),
                }
            return self._json({
                "stage": "authenticated",
                "ok": True,
                "ca_session": token,
                "authenticated_as": identity,
                "flag": read_flag(4),
                "note": "CA 认为这个连接就是 %s。你没输过密码，也没见过 NT hash。" % identity,
                "next": "带 X-CA-Session 头再 POST /certsrv/certfnsh.asp 申请证书。",
            })
        return self._fail("需要 NTLM Type1 或 Type3", 401, {"WWW-Authenticate": "NTLM"})

    # ---------------- L5：PKINIT 换 TGT ----------------

    def _asktgt(self, body, safe=False):
        try:
            cert = json.loads(b64d(body.get("cert", "")).decode("utf-8"))
        except Exception as exc:
            return self._fail("证书解析失败：%s" % exc)
        if not verify_ca_signature(cert):
            return self._json({"ok": False, "error": "CA 签名无效（别自己改 SAN）"}, 403)
        if cert.get("issuer") != CA_NAME:
            return self._json({"ok": False, "error": "不是受信任的企业 CA 签发"}, 403)
        if "clientAuth" not in cert.get("eku", []):
            return self._json({"ok": False, "error": "证书 EKU 不含 Client Authentication，不能做 PKINIT"}, 403)

        # 修复对照：KB5014754 之后要求强证书映射（证书里带账户 SID 扩展），
        # 只靠 UPN 字符串的弱映射不再被接受。本靶场签发的证书恰恰没有 SID。
        if safe:
            sid = cert.get("sid_extension")
            if not sid or sid not in STRONG_MAPPING:
                return self._json({
                    "ok": False,
                    "error": "弱证书映射被拒：证书缺少与账户 SID 匹配的强映射扩展",
                    "hint": "KB5014754 Full Enforcement 模式。加固后要改用 SID 扩展 / 显式映射。",
                }, 403)

        san = cert.get("san", "")
        upn = san.split("upn=", 1)[1] if "upn=" in san else ""
        if not upn:
            return self._json({"ok": False, "error": "SAN 里没有 UPN，KDC 映射不到账户"}, 403)
        # 真机里这一步是 KDC 拿 SAN 里的 UPN 去 NTDS 查账户、把 SID 塞进 PAC。
        # 这里直接信了字符串 —— 正是 ESC1 能提权的根因。
        account = upn.split("@")[0]
        tgt = make_tgt(account, ["Domain Admins", "Enterprise Admins",
                                 "Schema Admins", "Domain Users"])
        return self._json({
            "ok": True,
            "tgt": b64e(canonical(tgt)),
            "tgt_view": tgt,
            "note": "KDC 把 SAN 里的 UPN 直接映射成了域管，PAC 里带 Domain Admins。",
            "next": "带 X-TGT 头 GET /admin",
        })

    def _handle_admin(self):
        raw = self.headers.get("X-TGT", "")
        if not raw:
            return self._json({"ok": False, "error": "缺少 X-TGT"}, 401)
        try:
            tgt = json.loads(b64d(raw).decode("utf-8"))
        except Exception as exc:
            return self._json({"ok": False, "error": "TGT 解析失败：%s" % exc}, 400)
        if not verify_tgt(tgt):
            return self._json({"ok": False, "error": "TGT 签名无效或已过期"}, 403)
        if "Domain Admins" not in tgt.get("groups", []):
            return self._json({"ok": False, "error": "不是域管"}, 403)
        return self._json({
            "ok": True,
            "message": "欢迎，%s@%s（真机里下一步就是 DCSync）" % (tgt["user"], tgt["realm"]),
            "flag": read_flag(5),
        })


# 强证书映射白名单：加固后的 KDC 只认这些 SID。
STRONG_MAPPING = {"S-1-5-21-1000-1000-1000-500"}


def safe_checks():
    """
    修复对照页的数据来源。
    前 5 项真的调用 bank_safe_validate（跟 /bank/safe/transfer 是同一份代码），
    其中「重放第二次」是真的连打两次、由第二次的返回值说话。
    后 2 项是本模拟靶场没有实现的 TLS / LDAP 加固手段，明确标成 explanation，
    不冒充实测 —— 靶场里跑不出来的东西就得说清楚。
    """
    out = []

    def measured(label, blocked, why, extra=None):
        item = {"attack": label, "kind": "measured", "blocked_by": blocked,
                "blocked": bool(blocked), "why": why}
        if extra:
            item.update(extra)
        out.append(item)

    sample1 = make_sample(1)
    sample2 = make_sample(2)
    changed_nonce = dict(sample2, nonce=secrets.token_hex(8))  # sig 保持原样

    stale = {"from": "alice", "to": "shop", "amount": 10,
             "nonce": secrets.token_hex(8), "ts": int(time.time()) - 7200}
    stale["sig"] = sign_bank_safe(stale)  # 签名是对的，只是时间过期

    measured("L1 的报文（无 nonce / ts）打到安全接口",
             bank_safe_validate(sample1),
             "缺 nonce、缺时间戳，签名也没覆盖这些字段")
    measured("L2 的报文（签名没覆盖 nonce）打到安全接口",
             bank_safe_validate(sample2),
             "签名按全字段重算，原 sig 直接失效")
    measured("把 nonce 换掉但保留原签名",
             bank_safe_validate(changed_nonce),
             "改 nonce 就等于改了签名输入")
    measured("把时间戳改成 2 小时前（签名已按新时间戳重算）",
             bank_safe_validate(stale),
             "签名是对的，但时间窗不放行")

    good = {"from": "alice", "to": "shop", "amount": 10,
            "nonce": secrets.token_hex(8), "ts": int(time.time())}
    good["sig"] = sign_bank_safe(good)
    first = bank_safe_validate(good)
    second = bank_safe_validate(good)
    measured("把安全报文原样重放第二次", second,
             "第一次真的记了账，第二次撞上 nonce 一次性检查",
             {"first_attempt": "通过" if not first else first})

    for label, reasons, why in (
        ("ESC8：NTLM relay 到 Web Enrollment",
         ["EPA / 通道绑定校验失败（TLS channel binding 不在 NTLM AV pair 里）",
          "Web Enrollment 已禁用 NTLM，只走 Kerberos"],
         "中继者只能转发字节，改不了绑定在 TLS 通道上的哈希"),
        ("ESC1：注册者自填 SAN 申请域管证书",
         ["模板已关闭 ENROLLEE_SUPPLIES_SUBJECT",
          "manager approval 已开启", "Enroll ACL 已收窄",
          "KDC 要求强证书映射（KB5014754），无 SID 扩展直接拒"],
         "四道闸任意一道都能断链，真机建议全开"),
    ):
        out.append({
            "attack": label, "kind": "explanation", "blocked_by": reasons,
            "blocked": True, "why": why,
            "note": "真机加固清单；本模拟靶场没有 TLS / LDAP / NTDS，未做实测",
        })

    n_measured = sum(1 for item in out if item["kind"] == "measured")
    return {
        "checks": out,
        "summary": "%d 项实测拦截 + %d 项真机加固清单（说明，非实测）" %
                   (n_measured, len(out) - n_measured),
    }


def main():
    if not os.path.isdir(FLAG_DIR):
        raise SystemExit("flag 目录不存在：%s" % FLAG_DIR)
    server = ThreadingHTTPServer(("0.0.0.0", PORT), Handler)
    server.daemon_threads = True
    print("[+] replay-adcs 监听 0.0.0.0:%d  flag 目录 %s" % (PORT, FLAG_DIR), flush=True)
    print("[+] 入口 http://127.0.0.1:%d/" % PORT, flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
