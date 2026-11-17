"""一键验证四关（会依次跑 01~04，每关自己会先 /reset）。

    python3 log4shell/poc/verify.py

只用来对答案 / 回归测试。练习时建议一关一关手动跑。
"""

import pathlib
import subprocess
import sys

HERE = pathlib.Path(__file__).resolve().parent
SCRIPTS = ["01_probe.py", "02_rce.py", "03_bypass.py", "04_hardened.py"]


def main():
    results = []
    for name in SCRIPTS:
        print("\n" + "=" * 64)
        print(">>> " + name)
        print("=" * 64)
        rc = subprocess.call([sys.executable, str(HERE / name)], cwd=str(HERE))
        results.append((name, rc))

    print("\n" + "=" * 64)
    print("汇总")
    print("=" * 64)
    for name, rc in results:
        print("  %-20s %s" % (name, "PASS" if rc == 0 else "FAIL"))
    bad = [n for n, rc in results if rc != 0]
    if bad:
        print("\n先确认 ./log4shell/setup.sh 跑过，再看 docker logs log4shell-app")
        return 1
    print("\n四关全通。")
    return 0


if __name__ == "__main__":
    sys.exit(main())
