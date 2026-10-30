#!/usr/bin/env python3
# =============================================================================
#  L4 执行器：chroot 文件沙箱
# =============================================================================
#  chroot 只改「进程看到的 / 是哪一层目录」，它不创建新的命名空间、
#  不限制系统调用、也不回收已经打开的文件描述符。
#
#  所以 chroot 的唯一有效性来自一个前提：**沙箱里没有任何指向外部的句柄**。
#  只要进程手里还捏着一个 jail 外的目录 fd，就能
#
#      os.fchdir(fd)      # 把 cwd 挪回 jail 外面
#      os.chroot(".")     # 把根重新设成 jail 外面
#
#  跑回来。本关的 bug 就在下面第 3 步：父进程为了把审计日志写到容器外，
#  提前打开 "/" 并以 fd 3 交给沙箱进程 —— 这个 fd 就是那道后门。
#
#  现实对照：容器逃逸里常见的「挂进来的 socket / 保留的 fd / 未关闭的
#  目录句柄」是同一类问题。sandbox 的边界一旦有句柄漏出去就不再是边界。
# =============================================================================

import os
import resource
import sys

JAIL = "/jail"
LOG_FD = 3          # 审计日志的落盘句柄（父进程预先打开，见下面 open+dup2）


def run_in_jail(code: str) -> None:
    # 1. 打开「外部根」，固定成 fd 3 —— 这是本关唯一的漏洞
    outer = os.open("/", os.O_RDONLY | os.O_DIRECTORY)
    os.dup2(outer, LOG_FD, inheritable=True)

    # 2. 收缩视野：此后 / 就是 /jail
    os.chroot(JAIL)
    os.chdir("/")

    # 3. 限制 CPU 时间，防止死循环把父进程一起拖死
    resource.setrlimit(resource.RLIMIT_CPU, (3, 3))

    # 4. 沙箱里给的东西：os（「文件沙箱」总得有文件操作）+ 内置 print/open
    g = {
        "__builtins__": __builtins__,
        "os": os,
        "sys": sys,
        "print": print,
        "open": open,
    }
    try:
        exec(compile(code, "<jail>", "exec"), g)
    except BaseException as e:  # noqa: BLE001
        print("[jail] %s: %s" % (type(e).__name__, e))


def main():
    # 先把要用到的都读完，chroot 之后就读不到 stdin 了（其实是还能读，
    # 但子进程里没有必要）
    code = sys.stdin.read()

    pid = os.fork()
    if pid == 0:
        try:
            run_in_jail(code)
        finally:
            sys.stdout.flush()
            sys.stderr.flush()
            os._exit(0)

    os.waitpid(pid, 0)


if __name__ == "__main__":
    main()
