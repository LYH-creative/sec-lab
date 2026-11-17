"""redis-rce 靶场的公共小工具，只用标准库。

和 gopher 那套 poc 的区别：那边是把 RESP 塞进 gopher:// URL 借 SSRF 发出去，
这里是真的开一个 TCP socket 连 6379 —— 也就是 redis-cli 干的事，
只是我们手写一遍，好知道每一字节是怎么来的。
"""

import os
import socket

HOST = "127.0.0.1"
PORT = int(os.environ.get("LAB_REDIS_PORT", "16379"))   # 宿主映射端口，容器内还是 6379


def _detect_web_port():
    """web 端口取决于靶场怎么起的，这里探一下。

    并入主编排（docker-compose.yml）时是 8911 —— 跟其他靶场排成一列；
    单独跑 redis-rce/compose.yml 时是 18080。两个都试，谁开着用谁。
    要固定的话设环境变量 LAB_WEB_PORT。
    """
    forced = os.environ.get("LAB_WEB_PORT")
    if forced:
        return int(forced)
    for p in (8911, 18080):
        try:
            s = socket.create_connection((HOST, p), timeout=0.3)
            s.close()
            return p
        except OSError:
            continue
    return 8911


WEB = "http://%s:%d" % (HOST, _detect_web_port())


def resp(*args):
    """把一条命令编码成 RESP 数组。

    RESP 的规则就两条：
      *N\\r\\n        声明「这条命令有 N 个参数」
      $len\\r\\n数据\\r\\n   每个参数先报字节数，再跟内容
    len 必须是字节数不是字符数，否则中文之类的会被截断。
    """
    out = b"*%d\r\n" % len(args)
    for a in args:
        if isinstance(a, str):
            a = a.encode()
        out += b"$%d\r\n%s\r\n" % (len(a), a)
    return out


def connect(host=HOST, port=PORT, timeout=8):
    s = socket.create_connection((host, port), timeout=timeout)
    s.settimeout(timeout)
    return s


def _read_line(s):
    buf = b""
    while not buf.endswith(b"\r\n"):
        ch = s.recv(1)
        if not ch:
            raise ConnectionError("对端断开")
        buf += ch
    return buf[:-2]


def read_reply(s):
    """读一条完整的 RESP 回复。

    五种前缀，靶场里都会遇到：
      +  简单字符串（SET / CONFIG SET 返回的 OK）
      -  错误（CONFIG SET 被 protected config 挡住时就是它）
      :  整数（DEL 的返回值）
      $  批量字符串（GET 的返回值，$-1 表示 nil）
      *  数组（KEYS / CONFIG GET 的返回值）
    """
    head = s.recv(1)
    if not head:
        raise ConnectionError("对端断开")

    if head in (b"+", b"-", b":"):
        line = _read_line(s).decode("utf-8", "replace")
        return line if head != b":" else int(line)

    if head == b"$":
        n = int(_read_line(s))
        if n == -1:
            return None
        data = b""
        while len(data) < n + 2:
            chunk = s.recv(n + 2 - len(data))
            if not chunk:
                raise ConnectionError("bulk 没收全")
            data += chunk
        return data[:-2].decode("utf-8", "replace")

    if head == b"*":
        n = int(_read_line(s))
        if n == -1:
            return None
        return [read_reply(s) for _ in range(n)]

    raise ValueError("不认识的 RESP 前缀: %r" % head)


def run(s, *args):
    """发一条命令、读一条回复。返回 Python 原生结构。"""
    s.sendall(resp(*args))
    return read_reply(s)


def show(label, value):
    """打印结果，长内容折行，方便看清。"""
    if isinstance(value, list):
        print("%-22s %s" % (label, value))
    else:
        print("%-22s %s" % (label, value))


def find_flag(text, last=False):
    """挑出 flag。

    last=True 是必须的：L2 的 webshell 落在 RDB 文件里，而这份 RDB 快照
    正好包含 L1 那个 flag_l1 的明文。响应体里先出现的是 RDB 里的旧 flag，
    我们自己 echo 出来的才是真目标 —— 取最后一个。
    """
    import re
    hits = re.findall(r"flag\{[^}]*\}", text or "")
    if not hits:
        return None
    return hits[-1] if last else hits[0]
