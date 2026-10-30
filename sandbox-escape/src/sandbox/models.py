# =============================================================================
#  L3 的「业务模块」—— 看起来只是一堆数据类
# =============================================================================
#  反序列化白名单只放行了 {models} 这一个模块，因为它就是你的业务对象所在处。
#  但业务模块总得干点活：这里 version() 要调 git / 打包工具，于是文件顶部
#  import 了 os 和 subprocess。
#
#  记住这一点：白名单放行的是**模块**，模块里的 import 也跟着一起被放行了。
# =============================================================================

import os
import subprocess


class Point:
    """一个二维点。示例载荷就是它，序列化后 module=models, name=Point。"""

    def __init__(self, x=0, y=0):
        self.x = x
        self.y = y

    def __repr__(self):
        return "Point(x=%r, y=%r)" % (self.x, self.y)


class Tag:
    """一个标签。"""

    def __init__(self, name="", color="#888888"):
        self.name = name
        self.color = color

    def __repr__(self):
        return "Tag(%r, %r)" % (self.name, self.color)


def version():
    """取一下构建版本号（打包脚本和 git 都可能不可用，所以有兜底）。"""
    try:
        return subprocess.check_output(["git", "describe", "--always"]).decode().strip()
    except Exception:
        return "unknown"
