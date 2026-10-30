#!/usr/bin/env python3
# =============================================================================
#  Sandbox Escape Lab —— 关卡调度服务
# =============================================================================
#  只用标准库（http.server + subprocess），跟仓库里其他靶场的 poc 保持一致，
#  不装任何第三方依赖。
#
#  它做的事很笨但很安全：
#    - 每个关卡的用户代码都丢给一个**独立子进程**去跑（node / python3），
#      超时 10 秒直接 kill。这样即使被逃逸、被 os._exit、被死循环，
#      死的也只是子进程，服务本身不会倒。
#    - 真正危险的是子进程里发生的事 —— 那正是要你打的东西。
#
#  路由：
#    GET  /                 页面
#    GET  /style.css        样式
#    GET  /source/<key>     把关卡源码原样吐出来（沙箱代码是可以读的，
#                           读源码找漏洞本来就是这一关的一半）
#    POST /api/run/<level>  {"code": "..."} 或 {"data": "<base64>"}
# =============================================================================

import json
import os
import subprocess
import sys
import time
import traceback
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

APP = os.path.dirname(os.path.abspath(__file__))

PORT = int(os.environ.get("PORT", "8900"))
MAX_BODY = 128 * 1024          # 请求体上限
MAX_OUTPUT = 40 * 1024         # 回显上限，别让一屏 print 把浏览器卡死
TIMEOUT = 10                   # 单个沙箱子进程的墙钟超时（秒）

# 关卡 → (启动命令, 载荷类型)
#   code   : POST {"code": "..."}，直接把源码喂给 stdin
#   base64 : POST {"data": "..."}，base64 原样喂给 stdin
LEVELS = {
    "l1": (["node", os.path.join(APP, "sandbox", "l1_run.js")], "code"),
    "l2": ([sys.executable, "-u", os.path.join(APP, "sandbox", "l2_run.py")], "code"),
    "l3": ([sys.executable, "-u", os.path.join(APP, "sandbox", "l3_run.py")], "base64"),
    "l4": ([sys.executable, "-u", os.path.join(APP, "sandbox", "l4_run.py")], "code"),
}

# 源码浏览白名单（只暴露允许看的文件，不做路径拼接）
SOURCES = {
    "server": "server.py",
    "l1": "sandbox/l1_run.js",
    "l2": "sandbox/l2_run.py",
    "l3": "sandbox/l3_run.py",
    "l3-models": "sandbox/models.py",
    "l4": "sandbox/l4_run.py",
}

CONTENT_TYPES = {
    ".html": "text/html; charset=utf-8",
    ".css": "text/css; charset=utf-8",
    ".js": "text/javascript; charset=utf-8",
}


def read_text(path):
    with open(path, "rb") as f:
        return f.read()


class Handler(BaseHTTPRequestHandler):
    server_version = "sandbox-escape/1.0"

    # ---- 基础工具 --------------------------------------------------------
    def _send(self, code, body, ctype="text/plain; charset=utf-8"):
        if isinstance(body, str):
            body = body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _json(self, code, obj):
        self._send(code, json.dumps(obj, ensure_ascii=False),
                   "application/json; charset=utf-8")

    def log_message(self, fmt, *args):
        # 默认日志太吵，只留一行精简的
        sys.stderr.write("[web] %s %s\n" % (self.command, self.path))

    # ---- GET -------------------------------------------------------------
    def do_GET(self):
        path = self.path.split("?")[0]

        if path in ("/", "/index.html"):
            return self._send(200, read_text(os.path.join(APP, "web", "index.html")),
                              "text/html; charset=utf-8")

        if path == "/style.css":
            return self._send(200, read_text(os.path.join(APP, "web", "style.css")),
                              "text/css; charset=utf-8")

        if path.startswith("/source/"):
            key = path[len("/source/"):]
            rel = SOURCES.get(key)
            if not rel:
                return self._send(404, "没有这个文件\n")
            try:
                body = read_text(os.path.join(APP, rel)).decode("utf-8", "replace")
            except OSError:
                return self._send(500, "源码读取失败\n")
            return self._send(200, body)

        if path == "/healthz":
            return self._send(200, "ok\n")

        return self._send(404, "404\n")

    # ---- POST ------------------------------------------------------------
    def do_POST(self):
        path = self.path.split("?")[0]
        if not path.startswith("/api/run/"):
            return self._json(404, {"error": "not found"})

        level = path[len("/api/run/"):]
        if level not in LEVELS:
            return self._json(404, {"error": "没有这个关卡：%s" % level})

        # 限制请求体大小，别让人一上来就 OOM 服务
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            length = 0
        if length <= 0:
            return self._json(400, {"error": "空请求"})
        if length > MAX_BODY:
            return self._json(413, {"error": "载荷太大（上限 %d 字节）" % MAX_BODY})

        try:
            payload = json.loads(self.rfile.read(length).decode("utf-8", "replace"))
        except Exception:
            return self._json(400, {"error": "请求体不是合法 JSON"})

        cmd, kind = LEVELS[level]
        field = "data" if kind == "base64" else "code"
        body = (payload.get(field) or "")[:MAX_BODY]

        started = time.time()
        try:
            proc = subprocess.run(
                cmd,
                input=body.encode("utf-8"),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=TIMEOUT,
            )
            out = (proc.stdout + proc.stderr).decode("utf-8", "replace")
            code = proc.returncode
        except subprocess.TimeoutExpired as e:
            partial = b""
            for stream in (e.stdout, e.stderr):
                if stream:
                    partial += stream
            out = partial.decode("utf-8", "replace") + \
                "\n[sandbox] 超时（%d 秒），进程已终止\n" % TIMEOUT
            code = -1
        except Exception:
            return self._json(500, {"error": traceback.format_exc(limit=3)})

        if len(out) > MAX_OUTPUT:
            out = out[:MAX_OUTPUT] + "\n... （输出过长，已截断）\n"

        return self._json(200, {
            "output": out,
            "exit": code,
            "ms": int((time.time() - started) * 1000),
        })


def main():
    srv = ThreadingHTTPServer(("0.0.0.0", PORT), Handler)
    srv.daemon_threads = True
    print("[web] Sandbox Escape Lab listening on :%d" % PORT, flush=True)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
