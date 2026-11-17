#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ntlm.py —— NTLMv2 协议骨架，纯 Python 标准库实现

这个模块只做三件事：
  1. 算 NT hash（MD4(UTF-16LE(password))）。macOS 的 Python 3.12 链接的
     OpenSSL 3 默认禁用了 MD4，hashlib.new('md4') 会直接抛错，所以这里
     手写了一份 MD4。真实环境里 impacket / ntlmrelayx 用的是同样算法。
  2. 编解码 NTLM Type1 / Type2 / Type3 三种消息，字段布局按 MS-NLMP
     的 security buffer 结构来，不是随便拼的字符串。
  3. 生成并校验 NTLMv2 响应（NTProofStr + temp blob）。

教学上最关键的一点：
  验签只需要「NT hash + 服务器 challenge + Type3 里的响应」，
  不需要明文密码。所以 relay 攻击者只要把 victim 算好的 Type3
  原样搬到 CA，CA 就会认为这个连接是 victim 本人。
  全过程中攻击者既没有密码、也没有 hash，只有字节。

真机对照：
  Type1 = NEGOTIATE_MESSAGE   (客户端发起)
  Type2 = CHALLENGE_MESSAGE   (服务端给 8 字节 challenge)
  Type3 = AUTHENTICATE_MESSAGE(客户端用密码派生密钥算响应)
  HTTP 上三者走 Authorization / WWW-Authenticate: NTLM <base64>。
"""

import base64
import hashlib
import hmac
import os
import struct
import time

NTLMSSP = b"NTLMSSP\x00"

# MS-NLMP 里常见的协商标志。靶场里我们只用它填报文，不按位做严格分支。
F_UNICODE = 0x00000001
F_REQUEST_TARGET = 0x00000004
F_NTLM = 0x00000200
F_ALWAYS_SIGN = 0x00008000
F_TARGET_TYPE_DOMAIN = 0x00010000
F_EXTENDED_SESSIONSECURITY = 0x00080000
F_TARGET_INFO = 0x00800000
F_VERSION = 0x02000000
F_128 = 0x20000000
F_56 = 0x80000000

TYPE1_FLAGS = F_UNICODE | F_NTLM | F_REQUEST_TARGET | F_EXTENDED_SESSIONSECURITY | F_VERSION
TYPE2_FLAGS = (F_UNICODE | F_REQUEST_TARGET | F_NTLM | F_ALWAYS_SIGN |
               F_TARGET_TYPE_DOMAIN | F_EXTENDED_SESSIONSECURITY |
               F_TARGET_INFO | F_VERSION | F_128)
TYPE3_FLAGS = (F_UNICODE | F_NTLM | F_EXTENDED_SESSIONSECURITY |
               F_ALWAYS_SIGN | F_VERSION | F_128 | F_56)

# AV pair 的 ID（MS-NLMP 2.2.2.1）。Type2 的 TargetInfo 就是一串 AV pair。
AV_EOL = 0
AV_NB_COMPUTER = 1
AV_NB_DOMAIN = 2
AV_DNS_COMPUTER = 3
AV_DNS_DOMAIN = 4
AV_DNS_TREE = 5
AV_FLAGS = 6
AV_TIMESTAMP = 7
AV_TARGET_NAME = 9
AV_CHANNEL_BINDINGS = 10

AV_NAMES = {
    0: "MsvAvEOL", 1: "MsvAvNbComputerName", 2: "MsvAvNbDomainName",
    3: "MsvAvDnsComputerName", 4: "MsvAvDnsDomainName", 5: "MsvAvDnsTreeName",
    6: "MsvAvFlags", 7: "MsvAvTimestamp", 8: "MsvAvSingleHost",
    9: "MsvAvTargetName", 10: "MsvAvChannelBindings",
}


def b64e(raw):
    return base64.b64encode(raw).decode("ascii")


def b64d(text):
    return base64.b64decode(text)


# ---------------------------------------------------------------------------
#  MD4：RFC 1320，三个轮次各 16 步。
#  标准库没有可用的 MD4（OpenSSL 3 把它放进 legacy provider 了），
#  而 NT hash 的定义就是 MD4(password 的 UTF-16LE 字节)，绕不过去。
#  实现里 q = [a, b, c, d] 四个工作变量，每步按 a→d→c→b 的顺序轮换更新，
#  轮函数参数也跟着下标一起转，这样三轮可以共用同一个循环。
# ---------------------------------------------------------------------------

def _rol(value, bits):
    value &= 0xFFFFFFFF
    return ((value << bits) | (value >> (32 - bits))) & 0xFFFFFFFF


def md4(data):
    if isinstance(data, str):
        data = data.encode("utf-8")
    bit_len = (len(data) * 8) & 0xFFFFFFFFFFFFFFFF
    padded = bytearray(data)
    padded.append(0x80)
    while len(padded) % 64 != 56:
        padded.append(0)
    padded += struct.pack("<Q", bit_len)

    q = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476]

    def f_round1(x, y, z):
        return (x & y) | (~x & 0xFFFFFFFF & z)

    def f_round2(x, y, z):
        return (x & y) | (x & z) | (y & z)

    def f_round3(x, y, z):
        return x ^ y ^ z

    rounds = (
        (list(range(16)), (3, 7, 11, 19), f_round1, 0x00000000),
        ([0, 4, 8, 12, 1, 5, 9, 13, 2, 6, 10, 14, 3, 7, 11, 15],
         (3, 5, 9, 13), f_round2, 0x5A827999),
        ([0, 8, 4, 12, 2, 10, 6, 14, 1, 9, 5, 13, 3, 11, 7, 15],
         (3, 9, 11, 15), f_round3, 0x6ED9EBA1),
    )

    for offset in range(0, len(padded), 64):
        x = struct.unpack("<16I", bytes(padded[offset:offset + 64]))
        start = q[:]
        for order, shifts, func, const in rounds:
            for i, k in enumerate(order):
                idx = (4 - i % 4) % 4
                args = (q[(idx + 1) % 4], q[(idx + 2) % 4], q[(idx + 3) % 4])
                q[idx] = _rol(q[idx] + func(*args) + x[k] + const, shifts[i % 4])
        q = [(q[i] + start[i]) & 0xFFFFFFFF for i in range(4)]

    return struct.pack("<4I", *q)


def nt_hash(password):
    """NT hash = MD4(UTF-16LE(password))，也就是常说的 NTLM hash。"""
    return md4(password.encode("utf-16le"))


# ---------------------------------------------------------------------------
#  NTLMv2 响应
#  NTOWFv2 = HMAC_MD5(NT hash, Uppercase(User) + Domain)，都是 UTF-16LE。
#  temp    = 响应类型(2) + Z(6) + FILETIME(8) + 客户端 challenge(8)
#            + Z(4) + TargetInfo(AV pairs) + Z(4)
#  NTProofStr = HMAC_MD5(NTOWFv2, ServerChallenge + temp)
#  最终 NTResponse = NTProofStr + temp
#
#  注意：ServerChallenge 在 HMAC 的输入里。这就是 relay 的前提，也是
#  「中间人只能转发、不能改 challenge」的原因 —— 改了验签就失败。
# ---------------------------------------------------------------------------

def ntowf_v2(nt_hash_bytes, user, domain):
    identity = (user.upper() + domain).encode("utf-16le")
    return hmac.new(nt_hash_bytes, identity, hashlib.md5).digest()


def filetime_now():
    """Windows FILETIME：从 1601-01-01 起的 100 纳秒计数。"""
    return int((time.time() + 11644473600) * 10_000_000)


def av_pair(pair_id, value):
    if isinstance(value, str):
        value = value.encode("utf-16le") if pair_id not in (AV_TIMESTAMP, AV_FLAGS, AV_CHANNEL_BINDINGS) else value.encode()
    return struct.pack("<HH", pair_id, len(value)) + value


def parse_av_pairs(raw):
    """把 TargetInfo 拆成 [(id, 值字节), ...]，给 exp 脚本打印报文用。"""
    out = []
    pos = 0
    while pos + 4 <= len(raw):
        pair_id, length = struct.unpack_from("<HH", raw, pos)
        pos += 4
        value = raw[pos:pos + length]
        pos += length
        out.append((pair_id, value))
        if pair_id == AV_EOL:
            break
    return out


def build_target_info(domain="LAB", computer="ADCS", dns_domain="lab.local",
                      dns_computer="adcs.lab.local"):
    raw = b""
    raw += av_pair(AV_NB_DOMAIN, domain)
    raw += av_pair(AV_NB_COMPUTER, computer)
    raw += av_pair(AV_DNS_DOMAIN, dns_domain)
    raw += av_pair(AV_DNS_COMPUTER, dns_computer)
    raw += av_pair(AV_DNS_TREE, dns_domain)
    raw += av_pair(AV_TIMESTAMP, struct.pack("<Q", filetime_now()))
    raw += av_pair(AV_EOL, b"")
    return raw


def build_ntlmv2_response(nt_hash_bytes, user, domain, challenge,
                          target_info, client_challenge=None, timestamp=None):
    key = ntowf_v2(nt_hash_bytes, user, domain)
    client_challenge = client_challenge or os.urandom(8)
    timestamp = timestamp if timestamp is not None else filetime_now()
    temp = (b"\x01\x01" + b"\x00" * 6 +
            struct.pack("<Q", timestamp) +
            client_challenge + b"\x00" * 4 +
            target_info + b"\x00" * 4)
    proof = hmac.new(key, challenge + temp, hashlib.md5).digest()
    return proof + temp


def verify_ntlmv2_response(nt_hash_bytes, user, domain, challenge, response):
    """服务端视角：从响应里拆出 temp，重算 NTProofStr 比对前 16 字节。"""
    if len(response) < 20:
        return False
    proof, temp = response[:16], response[16:]
    key = ntowf_v2(nt_hash_bytes, user, domain)
    expected = hmac.new(key, challenge + temp, hashlib.md5).digest()
    return hmac.compare_digest(proof, expected)


# ---------------------------------------------------------------------------
#  Security Buffer：NTLM 消息里所有变长字段都用 <H len><H maxlen><I offset>
#  指向尾部 payload，而不是内联。下面两个函数负责打包 / 解包。
# ---------------------------------------------------------------------------

def _secbuf(length, offset):
    return struct.pack("<HHI", length, length, offset)


def _read_secbuf(msg, field_offset):
    length, _maxlen, offset = struct.unpack_from("<HHI", msg, field_offset)
    return msg[offset:offset + length]


def build_type1(domain="LAB", workstation="DC"):
    field_base = 8 + 4 + 4 + 8 + 8 + 8  # sig + type + flags + 2 secbuf + version
    d = domain.encode("utf-16le")
    w = workstation.encode("utf-16le")
    payload = d + w
    version = b"\x0a\x00\x00\x00\x00\x00\x00\x0f"  # Windows 10 / build 15
    return (NTLMSSP + struct.pack("<I", 1) + struct.pack("<I", TYPE1_FLAGS) +
            _secbuf(len(d), field_base) + _secbuf(len(w), field_base + len(d)) +
            version + payload)


def parse_type1(msg):
    if not msg.startswith(NTLMSSP) or len(msg) < 16:
        raise ValueError("不是合法的 NTLM Type1 消息")
    msg_type = struct.unpack_from("<I", msg, 8)[0]
    if msg_type != 1:
        raise ValueError("期望 Type1，收到 Type%d" % msg_type)
    flags = struct.unpack_from("<I", msg, 12)[0]
    return {
        "type": 1,
        "flags": flags,
        "domain": _read_secbuf(msg, 16).decode("utf-16le", "replace"),
        "workstation": _read_secbuf(msg, 24).decode("utf-16le", "replace"),
    }


def build_type2(challenge, target_info, target_name="LAB"):
    field_base = 8 + 4 + 8 + 4 + 8 + 8 + 8 + 8  # sig+type+targetname+flags+challenge+reserved+targetinfo+version
    name = target_name.encode("utf-16le")
    version = b"\x0a\x00\x00\x00\x00\x00\x00\x0f"
    return (NTLMSSP + struct.pack("<I", 2) + _secbuf(len(name), field_base) +
            struct.pack("<I", TYPE2_FLAGS) + challenge + b"\x00" * 8 +
            _secbuf(len(target_info), field_base + len(name)) +
            version + name + target_info)


def parse_type2(msg):
    if not msg.startswith(NTLMSSP) or len(msg) < 48:
        raise ValueError("不是合法的 NTLM Type2 消息")
    msg_type = struct.unpack_from("<I", msg, 8)[0]
    if msg_type != 2:
        raise ValueError("期望 Type2，收到 Type%d" % msg_type)
    flags = struct.unpack_from("<I", msg, 20)[0]
    challenge = msg[24:32]
    target_name = _read_secbuf(msg, 12).decode("utf-16le", "replace")
    target_info = _read_secbuf(msg, 40)
    return {
        "type": 2,
        "flags": flags,
        "challenge": challenge,
        "target_name": target_name,
        "target_info": target_info,
        "av_pairs": parse_av_pairs(target_info),
    }


def build_type3(nt_response, user, domain, workstation="DC", lm_response=b""):
    field_base = 8 + 4 + 8 * 6 + 4 + 8  # sig+type+6 secbuf+flags+version
    d = domain.encode("utf-16le")
    u = user.encode("utf-16le")
    w = workstation.encode("utf-16le")
    payload = b""
    fields = []
    for chunk in (lm_response, nt_response, d, u, w, b""):
        fields.append(_secbuf(len(chunk), field_base + len(payload)))
        payload += chunk
    version = b"\x0a\x00\x00\x00\x00\x00\x00\x0f"
    return (NTLMSSP + struct.pack("<I", 3) + b"".join(fields) +
            struct.pack("<I", TYPE3_FLAGS) + version + payload)


def parse_type3(msg):
    if not msg.startswith(NTLMSSP) or len(msg) < 64:
        raise ValueError("不是合法的 NTLM Type3 消息")
    msg_type = struct.unpack_from("<I", msg, 8)[0]
    if msg_type != 3:
        raise ValueError("期望 Type3，收到 Type%d" % msg_type)
    lm_response = _read_secbuf(msg, 12)
    nt_response = _read_secbuf(msg, 20)
    domain = _read_secbuf(msg, 28).decode("utf-16le", "replace")
    user = _read_secbuf(msg, 36).decode("utf-16le", "replace")
    workstation = _read_secbuf(msg, 44).decode("utf-16le", "replace")
    flags = struct.unpack_from("<I", msg, 60)[0]
    return {
        "type": 3,
        "flags": flags,
        "lm_response": lm_response,
        "nt_response": nt_response,
        "domain": domain,
        "user": user,
        "workstation": workstation,
    }


def make_type3_from_type2(nt_hash_bytes, user, domain, type2_msg, workstation="DC"):
    """客户端视角的完整一步：解析 Type2 → 算 NTLMv2 响应 → 造 Type3。"""
    info = parse_type2(type2_msg)
    response = build_ntlmv2_response(
        nt_hash_bytes, user, domain, info["challenge"], info["target_info"]
    )
    return build_type3(response, user, domain, workstation)


if __name__ == "__main__":
    # 自测：三个 RFC 1320 标准向量 + 一轮完整的 Type1/2/3 往返
    vectors = {
        b"": "31d6cfe0d16ae931b73c59d7e0c089c0",
        b"a": "bde52cb31de33e46245e05fbdbd6fb24",
        b"abc": "a448017aaf21d8525fc10ae87aa6729d",
        b"message digest": "d9130a8164549fe818874806e1c7014b",
    }
    for plain, expect in vectors.items():
        got = md4(plain).hex()
        assert got == expect, "MD4 向量不符: %r -> %s != %s" % (plain, got, expect)
    print("[+] MD4 四个标准向量全部通过")

    secret = nt_hash("Passw0rd!")
    t1 = build_type1()
    print("[+] Type1:", parse_type1(t1))
    challenge = b"\x01\x23\x45\x67\x89\xab\xcd\xef"
    t2 = build_type2(challenge, build_target_info())
    info = parse_type2(t2)
    print("[+] Type2 challenge =", info["challenge"].hex(),
          "| AV pairs =", [AV_NAMES.get(i, i) for i, _ in info["av_pairs"]])
    t3 = make_type3_from_type2(secret, "alice", "LAB", t2)
    parsed = parse_type3(t3)
    print("[+] Type3:", parsed["domain"] + "\\" + parsed["user"],
          "| NTResponse 长度 =", len(parsed["nt_response"]))
    ok = verify_ntlmv2_response(secret, "alice", "LAB", challenge,
                                parsed["nt_response"])
    print("[+] 服务端验签:", ok)
    assert ok
    tampered = verify_ntlmv2_response(nt_hash("WrongPass"), "alice", "LAB",
                                      challenge, parsed["nt_response"])
    print("[+] 换一个 NT hash 验签:", tampered)
    assert not tampered
    print("[+] 自测通过")
