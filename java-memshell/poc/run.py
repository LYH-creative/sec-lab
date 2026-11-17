#!/usr/bin/env python3
"""
Java 内存马靶场 · 自动演练 L0~L4（只用 Python 标准库）。

前提：先跑 ./java-memshell/up.sh，拿到一个「未注入」的干净容器。
本脚本按关卡打印每一步的真实响应；不改动靶场源码，也不重启容器。
L5（重启后消失）和容器内文件检查是 shell 侧动作，写在手册里手动做。
"""

import base64
import pathlib
import sys
import urllib.parse
import urllib.request

BASE = "http://127.0.0.1:19090"
ROOT = pathlib.Path(__file__).resolve().parents[1]
PROBE = {"X-Lab-Probe": "1"}


# 发一个 GET，返回 (状态码, 响应体文本)。超时设短一点，靶场起不来时快速失败。
def get(path, params=None, headers=None):
    url = BASE + path
    if params:
        url += "?" + urllib.parse.urlencode(params)
    req = urllib.request.Request(url, headers=headers or {})
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            return r.status, r.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace")


def first_line(text):
    return text.strip().splitlines()[0] if text.strip() else "(empty)"


def scan():
    return get("/__lab/scan")[1]


def rule(title):
    print("\n── " + title + " " + "─" * max(0, 46 - len(title)))


def main():
    try:
        alive = get("/")
    except Exception as e:
        print("[!] 连不上靶场：%s" % e)
        print("    先跑：./java-memshell/up.sh")
        return 1

    print("Java 内存马练习靶场 · 自动演练")
    print("目标：%s   状态码：%d" % (BASE, alive[0]))

    base_scan = scan()
    if "lab-probe-filter" in base_scan:
        print("\n[!] 目标已处于注入状态。先重置再跑：./java-memshell/up.sh")
        return 1

    # L0：把注入前的注册表基线摆出来，后面所有「多出来的东西」都以它为参照。
    rule("L0 · 基线")
    for line in base_scan.splitlines():
        if line.startswith(("jvm=", "context=", "evilClassOnClasspath=", "filterDefs=", "filterMaps=")):
            print("  " + line)
    codes = [l.strip() for l in base_scan.splitlines() if "codeSource=" in l and "no instance" not in l]
    print("  Filter 的 codeSource 共 %d 条，全部指向 /app/libs/*.jar：%s" %
          (len(codes), "是" if all("/app/libs/" in c for c in codes) else "否"))

    # L1：标准 API 是合法功能，但 Tomcat 只允许在启动阶段注册。
    rule("L1 · 标准 API 对照")
    st, body = get("/__lab/standard")
    for line in body.strip().splitlines():
        print("  " + line)

    # L2：攻击者侧把 .class 编成 base64，通过「模拟 RCE 入口」送进目标 JVM。
    rule("L2 · 注入")
    class_bytes = (ROOT / "attacker" / "evil" / "EvilFilter.class").read_bytes()
    b64 = base64.b64encode(class_bytes).decode("ascii")
    print("  攻击者侧：EvilFilter.class %d bytes → base64 %d chars" % (len(class_bytes), len(b64)))
    st, body = get("/__lab/inject", params={"b64": b64})
    print("  HTTP %d  %s" % (st, first_line(body)))
    if "injected:" not in body:
        print("[!] 注入失败，看日志：docker logs memshell-lab")
        return 1

    # L3：命中特征头才响应，其余原样放行；连 404 路径也会被 Filter 截获。
    rule("L3 · 命中与放行")
    st, hit = get("/", headers=PROBE)
    print("  GET / + X-Lab-Probe     → HTTP %d  %s" % (st, first_line(hit)))
    print("    " + "\n    ".join(hit.strip().splitlines()[1:]))
    st, plain = get("/")
    print("  GET / 无请求头          → HTTP %d  %s" % (st, first_line(plain)))
    st, other = get("/any/path", headers=PROBE)
    print("  GET /any/path + 请求头  → HTTP %d  %s" % (st, first_line(other)))

    # L4：磁盘查不到，但运行时注册表和 JVM 堆里都有。
    rule("L4 · 运行时检测")
    after = scan()
    for line in after.splitlines():
        if line.startswith(("filterDefs=", "filterMaps=", "evilClassOnClasspath=")):
            print("  " + line)
    print("  新增的 FilterDef：")
    lines = after.splitlines()
    for i, l in enumerate(lines):
        if "[lab-probe-filter]" in l:
            for x in lines[i:i + 4]:
                print("    " + x.strip())
            break
    print("  filterMaps 顺序（注意 lab-probe-filter 并不在数组第 0 位）：")
    in_maps = False
    for l in lines:
        if l.startswith("filterMaps="):
            in_maps = True
            continue
        if in_maps and l.startswith("  "):
            print("    " + l.strip())

    print("\n[L0~L4 完成] L5 手动做：docker restart memshell-lab，再打一次带请求头的 /")
    return 0


if __name__ == "__main__":
    sys.exit(main())
