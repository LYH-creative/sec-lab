#!/usr/bin/env python3
"""DVWA 一键建库脚本（纯标准库，零第三方依赖）

背景：
    DVWA 容器和数据库容器都起来之后，数据库里其实还是空的。
    官方要求你打开 http://127.0.0.1:8888/setup.php，手动点一下
    "Create / Reset Database" 按钮，它才会建表并写入初始数据。

    本脚本就是把这个手动动作自动化，两步：
        1) GET  setup.php  —— 拿到页面里隐藏的 CSRF 令牌 user_token
        2) POST setup.php  —— 带上令牌和 create_db 参数，提交建库请求

用法：
    python3 setup_dvwa.py                                  # 默认 8888 端口
    python3 setup_dvwa.py http://127.0.0.1:8888            # 显式指定地址
"""

import re
import sys
import urllib.parse
import urllib.request
import http.cookiejar


def main():
    base = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:8888"

    # 【为什么要 CookieJar】
    # DVWA 的 CSRF 令牌不是孤立的字符串，它存在服务端 session 里。
    # 第 1 步拿到的 token 只有在「同一个 session（同一个 PHPSESSID 这个 cookie）」
    # 的第 2 步里提交才有效。CookieJar 负责自动保存并回传这个 cookie。
    jar = http.cookiejar.CookieJar()
    opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))

    # ---------- 第 1 步：GET setup.php 取令牌 ----------
    try:
        with opener.open(f"{base}/setup.php", timeout=10) as resp:
            html = resp.read().decode("utf-8", "replace")
    except Exception as e:
        print(f"[!] 打不开 {base}/setup.php：{e}")
        print("    请先确认容器在跑：docker compose ps")
        sys.exit(1)

    # 页面里那行形如：<input type='hidden' name='user_token' value='a1b2c3...' />
    m = re.search(
        r"name=['\"]user_token['\"]\s+value=['\"]([0-9a-fA-F]+)['\"]", html
    )
    if not m:
        print("[!] 页面里没找到 user_token。")
        print("    可能原因：地址写错，或该页面不是 DVWA 的 setup.php")
        sys.exit(2)
    token = m.group(1)
    print(f"[*] 第 1 步 OK，取得 user_token = {token}")

    # ---------- 第 2 步：POST 提交建库 ----------
    # create_db 这个字段只要有值就会被源码里的 isset($_POST['create_db']) 判定为真，
    # 值本身写什么不重要，这里用界面按钮上的原文，便于对照。
    payload = urllib.parse.urlencode(
        {"user_token": token, "create_db": "Create / Reset Database"}
    ).encode()

    req = urllib.request.Request(f"{base}/setup.php", data=payload)
    try:
        with opener.open(req, timeout=60) as resp:
            out = resp.read().decode("utf-8", "replace")
    except Exception as e:
        print(f"[!] 提交建库请求失败：{e}")
        sys.exit(3)

    # ---------- 第 3 步：判定结果 ----------
    if "Setup successful" in out or "Database has been created" in out:
        # 顺便把脚本建好的数据表数量数出来，给一个可核对的量化结果
        tables = re.findall(r"Creating\s+(\w+)\s+table", out, re.IGNORECASE)
        print("[+] 建库成功！数据库 dvwa 已创建并写入初始数据。")
        if tables:
            print(f"[*] 本次创建的表：{', '.join(tables)}")
        print(f"[*] 现在可以访问 {base}/login.php 了")
        print("    账号 admin / 密码 password")
        sys.exit(0)
    elif "Setup failed" in out:
        print("[!] 建库失败（页面返回 Setup failed）。")
        print("    多半是 web 容器连不上 db 容器，检查：docker compose logs db")
        sys.exit(4)
    else:
        print("[?] 没匹配到明确的成功/失败标志，下面是响应片段，请人工确认：")
        print("-" * 50)
        print(out[:800])
        print("-" * 50)
        sys.exit(5)


if __name__ == "__main__":
    main()
