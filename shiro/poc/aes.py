"""
纯标准库 AES-128-CBC 加密 —— 只为了给 Shiro 的 rememberMe 套壳。

为什么不用 pycryptodome：
  这个仓库的 POC 一律零第三方依赖。CTF 现场装包经常失败，
  "ModuleNotFoundError: No module named 'Crypto'" 属于经典浪费时间。

为什么只需要"加密"：
  Shiro-721 的 padding oracle 全程只做异或和字节翻转，不需要 AES。
  真正需要 AES 的只有 Shiro-550：拿默认密钥把 CC6 字节加密成 cookie。
  所以这里只实现加密方向，省掉解密相关的逆 S 盒和逆列混淆。

代码结构（对照 FIPS-197）：
  1. S 盒 + 有限域乘法        —— 字节代换和列混淆的原料
  2. _expand_key()           —— 16 字节密钥扩展成 11 组轮密钥
  3. _encrypt_block()        —— 单块加密：SubBytes→ShiftRows→MixColumns→AddRoundKey ×10
  4. cbc_encrypt()           —— CBC 串联 + PKCS#7 填充
  5. self_test()             —— 用 FIPS-197 附录 C 的官方向量自检
"""

import base64
import os


# =============================================================================
#  1. S 盒
# =============================================================================
# AES 的 S 盒是 GF(2^8) 上的乘法逆元 + 仿射变换，标准实现直接查表。
# 这张表按行读，16 行 × 16 列，就是 FIPS-197 Figure 7 的那张。
SBOX = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
]


def _xtime(a):
    """GF(2^8) 里乘 2：左移一位，溢出就异或 0x1b（不可约多项式 x^8+x^4+x^3+x+1）"""
    a <<= 1
    if a & 0x100:
        a ^= 0x11b
    return a & 0xff


def _gmul(a, b):
    """GF(2^8) 乘法，用俄罗斯农民乘法，只为预计算 MUL2 / MUL3"""
    p = 0
    for _ in range(8):
        if b & 1:
            p ^= a
        a = _xtime(a)
        b >>= 1
    return p & 0xff


# 列混淆里只有乘 2 和乘 3，预计算成表比每轮算快一个数量级
MUL2 = [_gmul(i, 2) for i in range(256)]
MUL3 = [_gmul(i, 3) for i in range(256)]

RCON = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36]


# =============================================================================
#  2. 密钥扩展
# =============================================================================
def _expand_key(key):
    """
    16 字节密钥 → 11 组轮密钥（第 0 组用于初始 AddRoundKey）。

    AES-128 一共 44 个 32 位字（4 个初始 + 40 个扩展），每 4 个字拼成一组。
    每第 4 个字要做 RotWord + SubWord + 异或 Rcon，其余的字只是
    "前一个字 异或 上上轮同位置的字"。
    """
    if len(key) != 16:
        raise ValueError("AES-128 需要 16 字节密钥，收到 %d 字节" % len(key))

    w = [list(key[i * 4:(i + 1) * 4]) for i in range(4)]
    for i in range(4, 44):
        temp = list(w[i - 1])
        if i % 4 == 0:
            temp = temp[1:] + temp[:1]              # RotWord
            temp = [SBOX[b] for b in temp]          # SubWord
            temp[0] ^= RCON[i // 4 - 1]             # 异或轮常量
        w.append([w[i - 4][j] ^ temp[j] for j in range(4)])

    return [sum(w[r * 4:(r + 1) * 4], []) for r in range(11)]


# =============================================================================
#  3. 单块加密
# =============================================================================
def _shift_rows(s):
    """
    第 r 行循环左移 r 格。

    AES 的状态按列存：state[r][c] = s[r + 4*c]。
    所以第 r 行第 c 列的新值，来自同一行第 (c+r) mod 4 列。
    """
    out = [0] * 16
    for r in range(4):
        for c in range(4):
            out[r + 4 * c] = s[r + 4 * ((c + r) % 4)]
    return out


def _mix_columns(s):
    """每一列当成 GF(2^8) 上的多项式，乘固定的矩阵"""
    out = [0] * 16
    for c in range(4):
        a0, a1, a2, a3 = s[4 * c], s[4 * c + 1], s[4 * c + 2], s[4 * c + 3]
        out[4 * c] = MUL2[a0] ^ MUL3[a1] ^ a2 ^ a3
        out[4 * c + 1] = a0 ^ MUL2[a1] ^ MUL3[a2] ^ a3
        out[4 * c + 2] = a0 ^ a1 ^ MUL2[a2] ^ MUL3[a3]
        out[4 * c + 3] = MUL3[a0] ^ a1 ^ a2 ^ MUL2[a3]
    return out


def _encrypt_block(block, round_keys):
    s = [block[i] ^ round_keys[0][i] for i in range(16)]

    for rnd in range(1, 11):
        s = [SBOX[b] for b in s]          # SubBytes
        s = _shift_rows(s)                # ShiftRows
        if rnd != 10:                     # 第 10 轮没有列混淆
            s = _mix_columns(s)           # MixColumns
        rk = round_keys[rnd]
        s = [s[i] ^ rk[i] for i in range(16)]   # AddRoundKey

    return bytes(s)


# =============================================================================
#  4. CBC + PKCS#7
# =============================================================================
def pkcs7_pad(data, block_size=16):
    n = block_size - len(data) % block_size
    return data + bytes([n]) * n


def cbc_encrypt(key, iv, plaintext):
    """返回 iv 后面的密文部分（不含 iv）；Shiro 的 cookie 是 iv||ciphertext"""
    if len(iv) != 16:
        raise ValueError("iv 必须 16 字节")
    round_keys = _expand_key(key)
    data = pkcs7_pad(plaintext)
    out = bytearray()
    prev = iv
    for i in range(0, len(data), 16):
        block = bytes(a ^ b for a, b in zip(data[i:i + 16], prev))
        prev = _encrypt_block(block, round_keys)
        out += prev
    return bytes(out)


def shiro_encrypt(key_b64, plaintext):
    """
    Shiro 的 AesCipherService 默认参数：
        AES/CBC/PKCS5Padding，128 位密钥，每次随机 IV，IV 明文拼在密文前面
    最后整体 Base64（不是 URL-safe，用标准字母表）。
    """
    key = base64.b64decode(key_b64)
    if len(key) != 16:
        raise ValueError("key 解码后不是 16 字节：%s" % key_b64)
    iv = os.urandom(16)
    return base64.b64encode(iv + cbc_encrypt(key, iv, plaintext)).decode()


# =============================================================================
#  5. 自检
# =============================================================================
def self_test():
    """
    FIPS-197 附录 C.1 的官方向量：
        key       000102030405060708090a0b0c0d0e0f
        plain     00112233445566778899aabbccddeeff
        cipher    69c4e0d86a7b0430d8cdb78070b4c55a
    对不上就说明上面哪张表或哪一步写错了。
    """
    key = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
    plain = bytes.fromhex("00112233445566778899aabbccddeeff")
    expect = "69c4e0d86a7b0430d8cdb78070b4c55a"
    got = _encrypt_block(plain, _expand_key(key)).hex()
    assert got == expect, "AES 自检失败：%s != %s" % (got, expect)

    # CBC 再验一遍（NIST SP 800-38A F.2.1，前两块）
    key2 = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
    iv = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
    pt = bytes.fromhex("6bc1bee22e409f96e93d7e117393172a"
                       "ae2d8a571e03ac9c9eb76fac45af8e51")
    ct = cbc_encrypt(key2, iv, pt)[:32].hex()
    assert ct == "7649abac8119b246cee98e9b12e9197d5086cb9b507219ee95db113a917678b2", \
        "CBC 自检失败：%s" % ct
    return True


if __name__ == "__main__":
    self_test()
    print("[+] AES-128-CBC 自检通过（FIPS-197 C.1 + SP 800-38A F.2.1）")
