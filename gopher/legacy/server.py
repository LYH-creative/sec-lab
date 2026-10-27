#!/usr/bin/env python3
"""
Gopher(RFC 1436) 最小实现 + 内部 HTTP 网关。

为什么要自己写：
    public 库里的 gopher 服务端（pygopherd 之类）都带一堆特性，
    但我们要的是「能看清字节流」的东西 —— 一个 selector 进来，
    一个文件吐出去，中间不做任何解析。这样 L1 才能讲清楚
    「gopher 协议就是裸 TCP + 一行 selector + CRLF」。

两个监听端口：
    --gopher-port  Gopher 协议（默认 70）
    --http-port    内部 HTTP 网关（默认 0 = 不启）
                   /r?to=<url>  302 跳转，用来演示 SSRF 里
                   「curl 跟随重定向后会换协议」这个经典绕过点。
"""

import argparse
import os
import socket
import sys
import threading
from urllib.parse import unquote, urlparse, parse_qs

CRLF = "\r\n"


# ---------------------------------------------------------------- gopher 侧

def build_menu(root: str, host: str, port: int) -> bytes:
    """
    生成 gopher 菜单（gophermap）。

    每行格式是固定的五个字段，用 TAB 分隔：
        <type><display>\t<selector>\t<host>\t<port>\r\n

    type 常见取值：
        i  信息行（不显示链接）
        0  文本文件
        1  目录
        7  搜索
        g  gif     I  image    h  html    9  二进制
    """
    lines = ["iGopher 老服务 / 只读资料库\tfake\t(NULL)\t0"]
    for entry in sorted(os.listdir(root)):
        path = os.path.join(root, entry)
        if os.path.isfile(path):
            # 首字符 0 表示「文本文件」，点击后客户端会把 selector 当文件名发过来
            lines.append("0%s\t/%s\t%s\t%d" % (entry, entry, host, port))
    lines.append("i-- EOF --\tfake\t(NULL)\t0")
    # 文本块以单独一行 "." 结束（和 SMTP / finger 一样的老规矩）
    return (CRLF.join(lines) + CRLF + "." + CRLF).encode()


def handle_gopher(conn: socket.socket, root: str, host: str, port: int) -> None:
    conn.settimeout(5)
    buf = b""
    try:
        # 客户端只发一行 selector，以 CRLF 结束
        while b"\r\n" not in buf and len(buf) < 8192:
            chunk = conn.recv(2048)
            if not chunk:
                break
            buf += chunk

        selector = buf.decode("utf-8", "replace").split(CRLF)[0]
        if selector in ("", "/"):
            conn.sendall(build_menu(root, host, port))
            return

        # 去掉前导 / 和可能的 TAB 后缀（有些客户端会把 display string 也带上）
        rel = unquote(selector.lstrip("/").split("\t")[0])
        root_abs = os.path.abspath(root)
        target = os.path.normpath(os.path.join(root_abs, rel))

        # 靶场里也做了路径检查，免得不小心把镜像里的 /etc/passwd 读出去
        if not target.startswith(root_abs + os.sep) or not os.path.isfile(target):
            conn.sendall(b"3Not found\tfake\t(NULL)\t0\r\n.\r\n")
            return

        with open(target, "rb") as fh:
            conn.sendall(fh.read() + CRLF.encode() + b"." + CRLF.encode())
    except Exception as exc:  # noqa: BLE001 - 靶场服务，出错就断开
        sys.stderr.write("[gopher] %s\n" % exc)
    finally:
        conn.close()


def serve_gopher(port: int, root: str, host: str) -> None:
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("0.0.0.0", port))
    srv.listen(64)
    print("[gopher] listening 0.0.0.0:%d root=%s" % (port, root), flush=True)
    while True:
        conn, _ = srv.accept()
        threading.Thread(
            target=handle_gopher, args=(conn, root, host, port), daemon=True
        ).start()


# ------------------------------------------------------------------ http 侧

HTML_INDEX = """<!doctype html><meta charset="utf-8">
<title>内部网关</title>
<style>body{{font:14px/1.7 -apple-system,sans-serif;margin:40px;color:#1f2328}}</style>
<h2>内部跳转网关</h2>
<p>只给内部系统做 URL 转发用。</p>
<pre>GET /r?to=&lt;url&gt;   → 302 跳转</pre>
<p>本服务不提供任何文件内容，别乱试。</p>
"""


def handle_http(conn: socket.socket) -> None:
    conn.settimeout(5)
    try:
        buf = b""
        while b"\r\n\r\n" not in buf and len(buf) < 16384:
            chunk = conn.recv(4096)
            if not chunk:
                break
            buf += chunk

        request_line = buf.decode("utf-8", "replace").split(CRLF)[0]
        parts = request_line.split()
        if len(parts) < 2:
            conn.sendall(b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n")
            return

        parsed = urlparse(parts[1])
        query = parse_qs(parsed.query)

        if parsed.path == "/r":
            target = query.get("to", [""])[0]
            scheme = urlparse(target).scheme
            # 只做「协议合法性」检查，压根没想过 gopher 也能被重定向过去
            if scheme in ("http", "https", "gopher"):
                conn.sendall(
                    (
                        "HTTP/1.1 302 Found\r\n"
                        "Location: %s\r\n"
                        "Content-Length: 0\r\n"
                        "Connection: close\r\n\r\n" % target
                    ).encode()
                )
            else:
                conn.sendall(
                    b"HTTP/1.1 400 Bad Request\r\nContent-Length: 12\r\n\r\nbad scheme\n"
                )
        elif parsed.path in ("/", "/index.html"):
            body = HTML_INDEX.encode()
            conn.sendall(
                b"HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\n"
                b"Content-Length: " + str(len(body)).encode() + b"\r\n\r\n" + body
            )
        else:
            conn.sendall(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n")
    except Exception as exc:  # noqa: BLE001
        sys.stderr.write("[http] %s\n" % exc)
    finally:
        conn.close()


def serve_http(port: int) -> None:
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("0.0.0.0", port))
    srv.listen(64)
    print("[http] listening 0.0.0.0:%d" % port, flush=True)
    while True:
        conn, _ = srv.accept()
        threading.Thread(target=handle_http, args=(conn,), daemon=True).start()


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", default="/data")
    ap.add_argument("--gopher-port", type=int, default=70)
    ap.add_argument("--http-port", type=int, default=0)
    ap.add_argument("--host", default=socket.gethostname(), help="菜单里显示的 host")
    args = ap.parse_args()

    if args.http_port:
        threading.Thread(target=serve_http, args=(args.http_port,), daemon=True).start()
    serve_gopher(args.gopher_port, args.root, args.host)


if __name__ == "__main__":
    main()
