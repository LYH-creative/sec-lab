#!/usr/bin/env python3
# =============================================================================
#  L3 执行器：给 pickle 加一个「模块白名单」
# =============================================================================
#  思路是对的 —— pickle 的危险全在 find_class（GLOBAL / STACK_GLOBAL 指令
#  会按 "模块名.属性名" 去 import 并取属性），把模块卡住就行。
#
#  但这个实现漏了一个细节：STACK_GLOBAL 推上来的是两个字符串，
#  module 和 name。name 是**限定名**，可以带点号：
#
#      STACK_GLOBAL("models", "subprocess.check_output")
#
#  白名单校验的是 module（"models" 合法），然后 super().find_class() 会
#  按点号往 models 里一层层取属性 ——
#
#      models → models.subprocess → models.subprocess.check_output
#
#  于是被放行的模块里 import 过的一切，都成了你的跳板。
#
#  修法只有一条：白名单要校验「模块 + 完整限定名」，或者干脆别 pickle
#  不可信数据（改用 JSON）。
# =============================================================================

import base64
import io
import os
import pickle
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import models  # noqa: E402  —— 必须真的 import 进来，否则 sys.modules 里没有它


# 只允许业务对象所在模块；其他一律拒
ALLOWED_MODULES = {"models"}


class SafeUnpickler(pickle.Unpickler):
    def find_class(self, module, name):
        # 这里只看了 module，没看 name 里的点号
        if module not in ALLOWED_MODULES:
            raise pickle.UnpicklingError("模块 %r 不在白名单里（只允许 %s）"
                                         % (module, sorted(ALLOWED_MODULES)))
        return super().find_class(module, name)


def main():
    raw = sys.stdin.read().strip()
    if not raw:
        print("[sandbox] 没有收到数据")
        return
    try:
        data = base64.b64decode(raw, validate=True)
    except Exception:
        print("[sandbox] 载荷不是合法的 base64")
        return

    try:
        obj = SafeUnpickler(io.BytesIO(data)).load()
    except Exception as e:
        print("[sandbox] 反序列化失败：%s: %s" % (type(e).__name__, e))
        return

    print("[sandbox] 反序列化得到的对象：%r" % (obj,))


if __name__ == "__main__":
    main()
