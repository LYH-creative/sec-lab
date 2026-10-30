#!/usr/bin/env python3
# =============================================================================
#  L2 执行器：关键字黑名单 + 阉割版 builtins
# =============================================================================
#  这是真实世界最常见、也最没用的一种「沙箱」：正则/子串黑名单。
#  它只能拦住**字面量**。而 Python 里「名字」是可以在运行时拼出来的：
#
#      '_' + '_class_' + '_'   →  __class__
#      getattr(obj, 拼出来的名字) → 拿到原本被关键字挡住的属性
#
#  所以黑名单里每个被漏掉的名字都是一个洞。本关的黑名单是照着
#  「一个只想到 os / import / open 的开发者」写的 —— 看看漏了谁。
#
#  注意：沙箱代码是独立子进程跑的，所以它的输出（包括 system() 这类
#  直接写 fd 1 的东西）都会原样回到页面上。
# =============================================================================

import sys

# 开发者能想到的危险词，全在这里了（他以为）
BLACKLIST = [
    "import", "open", "eval", "exec", "__",
    "os", "subprocess", "builtins", "globals",
    "compile", "breakpoint",
]

# 只留「计算器该有的」内置函数。看起来人畜无害 —— 真的吗？
ALLOWED_BUILTINS = {
    "print": print, "len": len, "range": range, "str": str, "int": int,
    "float": float, "bool": bool, "list": list, "dict": dict, "tuple": tuple,
    "set": set, "sum": sum, "min": min, "max": max, "abs": abs,
    "sorted": sorted, "enumerate": enumerate, "zip": zip, "repr": repr,
    "format": format, "chr": chr, "ord": ord, "isinstance": isinstance,
    "getattr": getattr, "hasattr": hasattr,
}


def report_hits(src):
    """把命中的词连同行号、列号和那一行原文一起打出来。

    真实世界的黑名单大多只回一句 "contains forbidden word"，让人自己肉眼找。
    这里多给一点定位信息 —— 不代表它变强了，只是少浪费你十分钟。
    """
    found = []
    for lineno, line in enumerate(src.splitlines(), 1):
        for word in BLACKLIST:
            col = line.find(word)
            if col >= 0:
                found.append((word, lineno, col + 1, line))
    if not found:
        return False

    print("[sandbox] 拒绝执行：命中黑名单")
    for word, lineno, col, line in found:
        text = line if len(line) <= 72 else line[:72] + "…"
        print("          %r  第 %d 行第 %d 列" % (word, lineno, col))
        print("          %4d | %s" % (lineno, text))
    print("          提示：黑名单扫的是**全文**，字符串、注释、变量名里"
          "出现连续两个下划线都算。")
    return True


def main():
    src = sys.stdin.read()

    if report_hits(src):
        return

    g = {"__builtins__": ALLOWED_BUILTINS}
    try:
        exec(compile(src, "<sandbox>", "exec"), g)
    except BaseException as e:  # noqa: BLE001 —— 用户代码什么都能抛
        print("[sandbox] %s: %s" % (type(e).__name__, e))


if __name__ == "__main__":
    main()
