#!/usr/bin/env python3
"""
靶场里的「上游服务器」—— 跑在 gateway 容器上，扮演受害者在访问的那个网站。

它只做两件事：
  1. GET  /       返回一个极简登录页
  2. POST /login  把收到的用户名密码原样打印在 gateway 终端上

为什么要这么设计：ARP 欺骗本身只是「把流量引到自己机器」，真正要证明
「攻击成功」得有一个能被观察的秘密。这个 server 打印出来的那行密码，
就是攻击机抓包能拿到的东西，两边一对就说明流量确实被劫持了。
"""

import sys
import urllib.parse
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

LOGIN_PAGE = b"""<!doctype html>
<html><body>
<h3>Internal Admin</h3>
<form method="post" action="/login">
  user: <input name="user"><br>
  pass: <input name="pass" type="password"><br>
  <button>Login</button>
</form>
</body></html>
"""


class Handler(BaseHTTPRequestHandler):
    # 默认日志会打到 stderr 且格式啰嗦，这里改成自己一行式打印
    def log_message(self, fmt, *args):
        pass

    def _stamp(self):
        return datetime.now().strftime("%H:%M:%S")

    def do_GET(self):
        print(f"[{self._stamp()}] GET  {self.path}  <- {self.client_address[0]}", flush=True)
        if self.path.startswith("/login"):
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(LOGIN_PAGE)))
            self.end_headers()
            self.wfile.write(LOGIN_PAGE)
        else:
            body = b"upstream is alive\n"
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        raw = self.rfile.read(length)
        form = urllib.parse.parse_qs(raw.decode("utf-8", "replace"))
        user = form.get("user", [""])[0]
        password = form.get("pass", [""])[0]

        # 关键的一行：这是「服务器视角」看到的明文凭据
        print(f"[{self._stamp()}] POST {self.path}  <- {self.client_address[0]}", flush=True)
        print(f"[{self._stamp()}]      user={user!r}  pass={password!r}", flush=True)

        body = b"login ok\n"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 80
    srv = ThreadingHTTPServer(("0.0.0.0", port), Handler)
    print(f"upstream listening on 0.0.0.0:{port}", flush=True)
    srv.serve_forever()
