#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
webshell 静态排查脚本（纯标准库，零依赖）

用法：
    python3 hunt.py --docker webshell-hunt      # 直接扫容器现场（带权限/属主/时间）
    python3 hunt.py --root ./php                # 扫宿主机目录（只剩内容和相对路径）
    python3 hunt.py --docker webshell-hunt --json

它做的是应急响应里最耗时的第二步：把站点的所有文件按规则过一遍，
把可疑点连同行号、证据、判定理由排在前面。

注意：这些规则只负责"少漏"，不负责"定案"。分值最高的那几个也要人肉读代码，
因为真实环境里"看起来像后门"和"确实是后门"之间，差的是上下文。
"""

import argparse
import json
import os
import re
import statistics
import subprocess
import sys
from dataclasses import dataclass, field

# ---------------------------------------------------------------------------
# 扩展名分类
# ---------------------------------------------------------------------------
PHP_EXT = {".php", ".phtml", ".php3", ".php4", ".php5", ".php7", ".phar", ".inc"}
IMAGE_EXT = {".jpg", ".jpeg", ".png", ".gif", ".bmp", ".webp", ".ico"}
BACKUP_EXT = {".bak", ".old", ".orig", ".save", ".sav", ".swp", ".tmp", ".txt", ".log", ".zip"}

# ---------------------------------------------------------------------------
# 规则用的正则
# ---------------------------------------------------------------------------
# 危险函数 / 语言结构，括号里直接跟超全局变量
RE_DIRECT = re.compile(
    r"\b(eval|assert|system|exec|shell_exec|passthru|popen|proc_open|pcntl_exec|create_function)"
    r"\s*\(\s*\$_(?:GET|POST|REQUEST|COOKIE|SERVER|FILES)",
    re.I,
)

# 单独出现的 eval / assert —— 本身不一定是后门，但必须逐个看
RE_EVAL = re.compile(r"\b(eval|assert)\s*\(", re.I)

# 危险函数名，用于"拼接后再判断"
DANGER_WORDS = {
    "system", "exec", "shell_exec", "passthru", "popen", "proc_open",
    "eval", "assert", "create_function", "call_user_func", "call_user_func_array",
    "base64_decode", "gzinflate", "gzuncompress", "str_rot13", "hex2bin",
}

# 一串用 . 拼接的字符串字面量，例如 'sys' . 'tem'
RE_CONCAT_CHAIN = re.compile(r"(?:'[^']{0,40}'\s*\.\s*)+'[^']{0,40}'")

# 变量函数调用 —— $fn( ... ) 这种写法，静态扫描最容易漏
RE_VAR_CALL = re.compile(r"(?<![\w$>])\$[A-Za-z_]\w*\s*\(")

# 编码 / 解压函数，出现两种以上就基本是马
RE_ENCODE_WORDS = [
    "base64_decode", "gzinflate", "gzuncompress", "gzdecode",
    "str_rot13", "hex2bin", "convert_uudecode",
]

# .htaccess 把脚本交给解释器的写法
RE_HTACCESS = re.compile(
    r"(AddType\s+application/x-httpd-php|AddHandler\s+\S*php"
    r"|SetHandler\s+application/x-httpd-php|php_value\s+auto_prepend_file)",
    re.I,
)

# 时间线偏离阈值：mtime 与全站中位数相差超过这个天数就报出来
MTIME_DRIFT_DAYS = 180


@dataclass
class FileInfo:
    path: str
    size: int
    mode: str
    user: str
    group: str
    mtime: float
    parent_user: str = ""
    data: bytes = b""
    text: str = ""

    @property
    def ext(self):
        return os.path.splitext(self.path)[1].lower()

    @property
    def base(self):
        return os.path.basename(self.path)


@dataclass
class Hit:
    level: str
    rule: str
    path: str
    line: int
    snippet: str
    why: str


# ---------------------------------------------------------------------------
# 现场采集
# ---------------------------------------------------------------------------
def _sh(cmd):
    r = subprocess.run(cmd, capture_output=True)
    if r.returncode != 0:
        sys.exit("命令失败: %s\n%s" % (" ".join(cmd), r.stderr.decode("utf-8", "replace")))
    return r.stdout


def collect_docker(container, root, extra):
    """通过 docker exec 拿文件元数据和内容，元数据完全保留。"""
    # 先取一遍目录属主，用来判断"文件属主和所在目录属主是否一致"
    dir_owner = {}
    out = _sh(["docker", "exec", container, "find", root, "-type", "d", "-printf", r"%p\t%u\n"])
    for line in out.decode("utf-8", "replace").splitlines():
        p, _, u = line.partition("\t")
        dir_owner[p] = u
    for ep in extra:
        dir_owner[ep] = _sh(["docker", "exec", container, "stat", "-c", "%U", ep]).decode().strip()

    fmt = r"%p\t%s\t%M\t%u\t%G\t%T@\n"
    out = _sh(["docker", "exec", container, "find", root, "-type", "f", "-printf", fmt])
    files = []
    for line in out.decode("utf-8", "replace").splitlines():
        parts = line.split("\t")
        if len(parts) != 6:
            continue
        path, size, mode, user, group, mtime = parts
        files.append(FileInfo(
            path, int(size), mode, user, group, float(mtime),
            parent_user=dir_owner.get(os.path.dirname(path), ""),
        ))

    # 拿到 /var/www 之外的可疑位置（session 投毒、临时文件等）
    for ep in extra:
        out = _sh(["docker", "exec", container, "sh", "-c",
                   "ls -1 %s 2>/dev/null || true" % ep])
        for name in out.decode("utf-8", "replace").split():
            if not name.startswith("/"):
                name = os.path.join(ep, name)
            st = _sh(["docker", "exec", container, "stat", "-c", "%s\t%F\t%a\t%U\t%G\t%Y", name])
            try:
                size, ftype, mode, user, group, mtime = st.decode().strip().split("\t")
            except ValueError:
                continue
            if ftype != "regular file":
                continue
            files.append(FileInfo(name, int(size), "-" + mode, user, group, float(mtime)))

    for f in files:
        if f.size > 2 * 1024 * 1024:
            continue
        f.data = _sh(["docker", "exec", container, "cat", f.path])
        f.text = f.data.decode("utf-8", "replace")
    return files


def collect_local(root, extra):
    files = []
    for base in [root] + extra:
        if not os.path.exists(base):
            continue
        for dirpath, _dirs, names in os.walk(base):
            for n in names:
                p = os.path.join(dirpath, n)
                try:
                    st = os.stat(p)
                except OSError:
                    continue
                import stat as _stat
                mode = _stat.filemode(st.st_mode)
                files.append(FileInfo(
                    p, st.st_size, mode,
                    str(st.st_uid), str(st.st_gid), st.st_mtime,
                ))
    for f in files:
        if f.size > 2 * 1024 * 1024:
            continue
        with open(f.path, "rb") as fh:
            f.data = fh.read()
        f.text = f.data.decode("utf-8", "replace")
    return files


# ---------------------------------------------------------------------------
# 规则
# ---------------------------------------------------------------------------
def scan(files):
    hits = []

    def add(level, rule, f, line, snippet, why):
        hits.append(Hit(level, rule, f.path, line, snippet.strip()[:160], why))

    # 时间线基准：全站文件 mtime 的中位数
    all_mtimes = [f.mtime for f in files if f.ext in PHP_EXT or f.ext in IMAGE_EXT]
    baseline = statistics.median(all_mtimes) if all_mtimes else 0

    for f in files:
        lines = f.text.splitlines()

        # --- 规则 1：危险函数直接吃外部输入 ---
        for i, ln in enumerate(lines, 1):
            if RE_DIRECT.search(ln):
                add("HIGH", "外部输入直连危险函数", f, i, ln,
                    "参数直接来自请求，等于把命令执行权交给访问者。")

        # --- 规则 2：eval / assert 单独出现 ---
        for i, ln in enumerate(lines, 1):
            if RE_EVAL.search(ln) and not RE_DIRECT.search(ln):
                add("MED", "eval/assert 使用点", f, i, ln,
                    "eval 不是业务代码的常规写法，需要确认参数来源是否可控。")

        # --- 规则 3：编码 + 执行 组合 ---
        enc_found = [w for w in RE_ENCODE_WORDS if w in f.text]
        if len(enc_found) >= 2:
            has_sink = any(k in f.text for k in ("eval", "include", "require", "file_put_contents"))
            add("HIGH" if has_sink else "MED", "多层编码载荷", f, 0,
                "编码函数: " + ", ".join(enc_found),
                "同时出现多种编码/解压函数，且有落盘或执行动作，典型混淆马结构。")

        # --- 规则 4：字符串拼接后是危险函数名 ---
        for i, ln in enumerate(lines, 1):
            for chain in RE_CONCAT_CHAIN.finditer(ln):
                merged = "".join(re.findall(r"'([^']*)'", chain.group(0)))
                if merged in DANGER_WORDS:
                    add("HIGH", "函数名被拆开拼接", f, i, ln,
                        "拼接结果是 %r，故意绕过关键字扫描。" % merged)

        # --- 规则 5：变量函数调用 ---
        for i, ln in enumerate(lines, 1):
            if RE_VAR_CALL.search(ln) and "function" not in ln and not ln.strip().startswith("*"):
                add("MED", "变量函数调用", f, i, ln,
                    "函数名运行时才确定，需要看这个变量能不能被请求控制。")

        # --- 规则 6：图片里藏 PHP ---
        if f.ext in IMAGE_EXT and b"<?php" in f.data:
            add("HIGH", "图片内嵌 PHP 代码", f, 0, "文件尾: " + repr(f.data[-90:]),
                "合法图片 + 尾部 PHP，配合 .htaccess 的 AddType 就能当脚本执行。")

        # --- 规则 7：.htaccess 改写解析规则 ---
        if f.base == ".htaccess":
            for i, ln in enumerate(lines, 1):
                if RE_HTACCESS.search(ln):
                    add("HIGH", "上传目录改写解析规则", f, i, ln,
                        "把非 .php 后缀交给 PHP 解释器，是图片马能跑起来的前提。")

        # --- 规则 8：隐藏文件 ---
        if f.base.startswith(".") and f.base not in (".htaccess", ".htpasswd", ".gitignore"):
            add("MED", "隐藏文件", f, 0, f.base,
                "以点开头，ls 默认看不见，只有 find 或 ls -a 才能发现。")

        # --- 规则 9：备份 / 临时残留 ---
        if f.ext in BACKUP_EXT and "<?php" in f.text:
            add("MED", "备份文件含 PHP 代码", f, 0, f.base,
                "备份文件通常不被解析，但会以源码形式直接返回给访问者。")

        # --- 规则 10：时间线偏离中位数 ---
        if baseline and abs(f.mtime - baseline) > MTIME_DRIFT_DAYS * 86400:
            drift = int((f.mtime - baseline) / 86400)
            add("MED", "时间戳远离基线", f, 0,
                "%+d 天（基线中位数）" % drift,
                "要么是入侵时间点，要么是被人为改过 mtime 想混进老文件里。")

        # --- 规则 11：属主异常 ---
        # Web 进程属于 www-data；它写出来的文件，属主必然是 www-data。
        # 如果这类文件出现在 root 拥有的目录里，说明有目录穿越或任意写入。
        WEB_USERS = {"www-data", "apache", "nginx", "httpd", "33", "48", "501"}
        ROOT_USERS = {"root", "0"}
        if f.ext in PHP_EXT and f.user in WEB_USERS and f.parent_user in ROOT_USERS:
            add("MED", "属主与目录不一致", f, 0,
                "文件属主 %s，所在目录属主 %s" % (f.user, f.parent_user),
                "Web 进程能往 root 拥有的目录里写 .php，说明存在任意文件写入。")

        # --- 规则 12：权限异常 ---
        if f.ext in PHP_EXT and f.mode not in ("-rw-r--r--", "-rw-r-----", "-rwxr-xr-x"):
            add("LOW", "权限异常", f, 0, f.mode,
                "全站 .php 都是 644，唯独这个不是，多半是被单独改过。")

        # --- 规则 13：session / 临时目录产物 ---
        if f.base.startswith("sess_") or f.base.startswith(".wpc-"):
            if "<?php" in f.text:
                add("HIGH", "非标准目录里的会话/临时文件", f, 0, f.path,
                    "session 文件里出现 PHP 代码，属于先落一个文件、等 LFI 来包含的手法。")

    # 同一位置的多个命中合并：留最高级别，但理由要全部保留，否则线索会丢
    rank = {"HIGH": 0, "MED": 1, "LOW": 2}
    merged = {}
    for h in hits:
        key = (h.path, h.line)
        if key not in merged:
            merged[key] = h
        else:
            cur = merged[key]
            if rank[h.level] < rank[cur.level]:
                h.why = cur.why.rstrip("。") + "；另: " + h.why
                h.rule = cur.rule + " / " + h.rule
                merged[key] = h
            else:
                cur.why = cur.why.rstrip("。") + "；另: " + h.why
                if h.rule not in cur.rule:
                    cur.rule += " / " + h.rule
    return sorted(merged.values(), key=lambda h: (rank[h.level], h.path, h.line))


# ---------------------------------------------------------------------------
# 输出
# ---------------------------------------------------------------------------
def render(hits, files, root, baseline):
    out = []
    out.append("被排查目录: %s" % root)
    out.append("文件总数:   %d" % len(files))
    out.append("时间基线:   %s（全站 mtime 中位数）"
               % __import__("datetime").datetime.fromtimestamp(baseline).strftime("%Y-%m-%d %H:%M"))
    out.append("")

    buckets = {"HIGH": [], "MED": [], "LOW": []}
    for h in hits:
        buckets[h.level].append(h)

    label = {"HIGH": "高度可疑", "MED": "需要人工确认", "LOW": "低风险线索"}
    for level in ("HIGH", "MED", "LOW"):
        items = buckets[level]
        out.append("── %s（%d）%s" % (level, len(items), "─" * 40))
        if not items:
            out.append("   （无）")
        for h in items:
            out.append("   [%s] %s" % (level, h.rule))
            loc = h.path if not h.line else "%s:%d" % (h.path, h.line)
            out.append("       位置: %s" % loc)
            out.append("       证据: %s" % h.snippet.replace("\n", " "))
            out.append("       理由: %s" % h.why)
        out.append("")

    out.append("── 小结 %s" % ("─" * 46))
    files_hit = len({h.path for h in hits})
    out.append("命中文件 %d / %d，HIGH %d 项"
               % (files_hit, len(files), len(buckets["HIGH"])))
    out.append("")
    out.append("下一步：HIGH 项逐条读上下文，MED 项确认业务是否需要；")
    out.append("       命中不了的地方，靠日志和进程行为兜底（见 answer/ANSWERS.md 第 5 步）。")
    return "\n".join(out)


def main():
    ap = argparse.ArgumentParser(description="webshell 静态排查")
    ap.add_argument("--docker", help="容器名，直接从容器里读取现场")
    ap.add_argument("--root", default="/var/www/html", help="扫描根目录")
    ap.add_argument("--extra", nargs="*", default=["/var/tmp", "/var/lib/php/sessions"],
                    help="额外检查的目录")
    ap.add_argument("--json", action="store_true", help="输出 JSON")
    args = ap.parse_args()

    if args.docker:
        files = collect_docker(args.docker, args.root, args.extra)
    else:
        files = collect_local(args.root, args.extra)

    if not files:
        sys.exit("没有采集到文件，检查路径或容器名。")

    hits = scan(files)

    if args.json:
        print(json.dumps([h.__dict__ for h in hits], ensure_ascii=False, indent=2))
        return

    mtimes = [f.mtime for f in files if f.ext in PHP_EXT or f.ext in IMAGE_EXT]
    baseline = statistics.median(mtimes) if mtimes else 0
    print(render(hits, files, args.root, baseline))


if __name__ == "__main__":
    main()
