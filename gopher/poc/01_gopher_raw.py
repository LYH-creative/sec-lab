"""L1 · Gopher 协议本体

这一关没有 SSRF，就是直接对 Gopher 服务说话。
目的是让你看清：协议本身只有「一行 selector + CRLF」。

跑法：
    python3 01_gopher_raw.py
等价的手工命令：
    curl -v 'gopher://127.0.0.1:7070/1/'
    curl -v 'gopher://127.0.0.1:7070/0/l1.txt'
"""

import socket
import sys

HOST, PORT = "127.0.0.1", 7070


def talk(selector, host=HOST, port=PORT):
    """发一行 selector，把服务端吐回来的字节全收下。"""
    with socket.create_connection((host, port), timeout=3) as s:
        s.sendall((selector + "\r\n").encode())
        buf = b""
        while True:
            chunk = s.recv(4096)
            if not chunk:
                break
            buf += chunk
        return buf


def main():
    menu = talk("/")
    print("=== 根菜单（原始字节 %d 个）===" % len(menu))
    print(menu.decode("utf-8", "replace"))

    # 菜单里每行是 type + display \t selector \t host \t port
    # type 为 0 的是文本文件，把 selector 抠出来就行
    files = []
    for line in menu.decode("utf-8", "replace").split("\r\n"):
        if line.startswith("0"):
            parts = line.split("\t")
            if len(parts) >= 2:
                files.append(parts[1])
    print("=== 菜单里的文件 ===")
    for f in files:
        print("  ", f)

    for f in files:
        if "l1" in f:
            print("\n=== 读 %s ===" % f)
            print(talk("/" + f.lstrip("/")).decode("utf-8", "replace"))
            return 0

    print("没找到 l1.txt，检查一下服务是不是起来了", file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
