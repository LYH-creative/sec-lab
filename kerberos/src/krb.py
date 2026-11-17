"""
krb.py - 迷你 Kerberos 域的共享密码学层（教学仿真，Python 标准库实现）

这个文件被容器内 KDC 服务端和宿主机攻击脚本共同导入，保证「伪造」发生在
客户端本地、而不是服务端帮忙造假：只有持有对应密钥的一方才能造出会被信任
的票据，这正是黄金 / 白银票据成立的根本原因。

与真实 Windows AD 的对应关系（务必先读懂，避免把仿真当成真实协议）：
  真实 TGT 用 krbtgt 的 NT hash / AES key 加密，客户端打不开；
  真实 TGS 用目标服务账户的密钥加密，只有该服务能解开；
  这里改成「可读的 JSON + 用对应密钥算的 HMAC-SHA256 封印」。
  封印不是加密，但等价表达了核心性质：没有密钥就造不出能通过校验的票据，
  而可读的票据让 klist 能直接看到 PAC、SID、SPN、生命周期，便于练习对照。

PAC（Privilege Attribute Certificate）同样仿真为两个签名：
  kdc_sig 用 krbtgt 密钥签 —— 攻击者只有服务密钥时伪造不出来；
  svc_sig 用服务密钥签 —— 白银票据持有者可以伪造。
服务端默认只校验 svc_sig；开启完整 PAC 签名校验后才检查 kdc_sig。
这正是 2023 年 KB5020805 之后白银票据被挡、黄金票据仍然有效的分界线。

域内所有密钥都刻意硬编码为固定值，方便逐字节对照实验输出；真实环境里
这些值绝不会出现在源码中，只会通过 DCSync / ntds.dit / 本地 SAM 泄露。
"""

import base64
import hashlib
import hmac
import json
import secrets

REALM = "LAB.LOCAL"
DOMAIN_SID = "S-1-5-21-1111111111-2222222222-3333333333"

RID_ADMIN = 500
RID_ALICE = 1105
GROUP_DOMAIN_USERS = DOMAIN_SID + "-513"
GROUP_DOMAIN_ADMINS = DOMAIN_SID + "-512"

TEN_HOURS = 10 * 60 * 60
TEN_YEARS = 10 * 365 * 24 * 60 * 60

# krbtgt 初始密钥。真实域里这是 krbtgt 账户的 NT hash，只能通过 DCSync 拿到。
KRBTGT_KEY_V0 = "8f3c1a90b7d24e6f5a0c19d8e7b6f5a4c3"

# 各服务的账户密钥。真实域里对应机器账户 XXX$ 或服务账户的 NT hash。
# 注意 files 这台机器上的 cifs/ 与 http/ 共用同一把机器账户密钥：真实 AD 中
# 同一主机的多个 HOST SPN 都注册在同一个计算机账户下，不是每个 SPN 一把密钥。
# 这一点决定了 L4：换 SPN 时服务端能解开票据，但会因票据里的 SPN 字段不符而拒绝；
# 如果换成另一台机器的服务（密钥不同），则连解密都过不了，直接 bad_seal。
SERVICE_KEYS = {
    "http/portal.lab.local": "c1f0a2b34d5e6f708192a3b4c5d6e7f809",
    "cifs/files.lab.local": "d2e1b3c45f6a708192b3c4d5e6f70819a2",
    "http/files.lab.local": "d2e1b3c45f6a708192b3c4d5e6f70819a2",
    "cifs/dc.lab.local": "f4a3d5e67b8c920314d5e6f70819203c4",
}

# 服务定义。required_group 决定 PAC 里必须出现哪个组 SID 才能访问。
SERVICES = {
    "http/portal.lab.local": {
        "desc": "内网门户（普通域用户可访问）",
        "required_group": GROUP_DOMAIN_USERS,
    },
    "cifs/files.lab.local": {
        "desc": "文件服务器共享（仅域管）",
        "required_group": GROUP_DOMAIN_ADMINS,
    },
    "http/files.lab.local": {
        "desc": "文件服务器 Web 管理（仅域管）",
        "required_group": GROUP_DOMAIN_ADMINS,
    },
    "cifs/dc.lab.local": {
        "desc": "域控 C$ 共享（仅域管）",
        "required_group": GROUP_DOMAIN_ADMINS,
    },
}

# 域用户。只把 alice 的口令交给练习者，Administrator 口令未知。
USERS = {
    "alice": {
        "password": "alice123",
        "sid": DOMAIN_SID + "-" + str(RID_ALICE),
        "groups": [GROUP_DOMAIN_USERS],
    },
    "Administrator": {
        "password": None,
        "sid": DOMAIN_SID + "-" + str(RID_ADMIN),
        "groups": [GROUP_DOMAIN_USERS, GROUP_DOMAIN_ADMINS],
    },
}


def canonical(obj):
    """把字典序列化成稳定字节串，作为 HMAC 的输入，避免键顺序影响签名。"""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def mac(key, payload):
    """用指定密钥对字符串算 HMAC-SHA256 十六进制摘要。"""
    return hmac.new(key.encode(), payload.encode(), hashlib.sha256).hexdigest()


def seal(obj, key):
    """用密钥封印一份票据：base64(JSON) + "." + HMAC。

    这里的 HMAC 等价于真实 Kerberos 里「用该账户密钥加密」的信任来源。
    服务端会用同一把密钥校验封印，校验不过就说明票据不是持钥者造的。
    """
    payload = base64.urlsafe_b64encode(canonical(obj)).decode().rstrip("=")
    return payload + "." + mac(key, payload)


def unseal(token, keys):
    """用候选密钥列表校验封印并返回票据字典；全部不匹配则返回 None。

    keys 允许传多个，对应真实 KDC 同时接受「当前 + 上一个」krbtgt 密钥。
    这个细节决定了「重置一次 krbtgt 密码杀不掉黄金票据」。
    """
    if not isinstance(token, str) or "." not in token:
        return None
    payload, signature = token.rsplit(".", 1)
    for key in keys:
        if hmac.compare_digest(mac(key, payload), signature):
            try:
                raw = base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4))
                return json.loads(raw.decode())
            except Exception:
                return None
    return None


def peek(token):
    """不校验密钥，只解出票据明文，模拟 klist 查看票据内容。"""
    if not isinstance(token, str) or "." not in token:
        return None
    payload = token.rsplit(".", 1)[0]
    try:
        raw = base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4))
        return json.loads(raw.decode())
    except Exception:
        return None


def fingerprint(token):
    """票据指纹，供 KDC 记录「这张 TGS 是不是我发出去的」。"""
    return hashlib.sha256(token.encode()).hexdigest()[:16]


def pac_body(user, sid, groups, logon_time):
    """构造 PAC 主体：用户名、SID、组 SID、登录时间。权限完全由 groups 决定。"""
    return {
        "user": user,
        "sid": sid,
        "groups": list(groups),
        "logon_time": logon_time,
    }


def sign_pac(pac, krbtgt_key, service_key):
    """给 PAC 补上 KDC 签名与服务签名。持 krbtgt 密钥者才能签出有效 kdc_sig。"""
    result = dict(pac)
    raw = canonical(result).decode()
    result["kdc_sig"] = mac(krbtgt_key, raw)
    result["svc_sig"] = mac(service_key, raw)
    return result


def verify_pac(pac, key, field):
    """校验 PAC 的某个签名。签名不合法返回 False。"""
    clean = {k: v for k, v in pac.items() if k not in ("kdc_sig", "svc_sig")}
    expected = mac(key, canonical(clean).decode())
    return hmac.compare_digest(expected, str(pac.get(field, "")))


def new_krbtgt_key():
    """生成轮换用的新 krbtgt 密钥，模拟管理员重置 krbtgt 密码。"""
    return secrets.token_hex(16)


def spn_key(spn):
    """按 SPN 取服务账户密钥。"""
    return SERVICE_KEYS.get(spn)


def service_info(spn):
    """按 SPN 取服务定义。"""
    return SERVICES.get(spn)
