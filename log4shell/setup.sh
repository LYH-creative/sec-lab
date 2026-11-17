#!/usr/bin/env bash
# =============================================================================
#  Log4Shell 靶场初始化：等服务就绪 + 清空上一轮的事件
#  可重复执行；每次练习前跑一遍，保证 /events 是干净起点。
# =============================================================================
set -euo pipefail
cd "$(dirname "$0")"

say() { printf '\033[36m[*]\033[0m %s\n' "$*"; }
ok()  { printf '\033[32m[+]\033[0m %s\n' "$*"; }
warn(){ printf '\033[33m[!]\033[0m %s\n' "$*" >&2; }

for f in flags/l1.flag flags/l2.flag flags/l3.flag; do
  [ -f "$f" ] || { warn "缺 $f"; exit 1; }
done

# 等 attacker 的 HTTP 起来（它同时托管 /events 和 .class）
ready=0
for i in $(seq 1 45); do
  if curl -fsS --max-time 2 http://127.0.0.1:19089/ >/dev/null 2>&1; then
    ready=1; break
  fi
  sleep 1
done
[ "$ready" -eq 1 ] || {
  warn "attacker 没起来，先跑：docker compose -f log4shell/compose.yml up -d --build"
  exit 1
}

# 等三个 JVM 都能应答（8082 用 2.17.1，启动稍慢）
for p in 19080 19081 19082; do
  for i in $(seq 1 30); do
    curl -fsS --max-time 2 -A "seclab-healthcheck" \
      "http://127.0.0.1:$p/" >/dev/null 2>&1 && break
    sleep 1
  done
done

curl -fsS --max-time 3 http://127.0.0.1:19089/reset >/dev/null
ok "事件已清空"

echo
ok "就绪："
echo "   L1~L3  vuln      http://127.0.0.1:19080/   log4j 2.14.1 · trustURLCodebase=true"
echo "   L4-1   jdk       http://127.0.0.1:19081/   log4j 2.14.1 · JDK 默认加固"
echo "   L4-2   patched   http://127.0.0.1:19082/   log4j 2.17.1"
echo "   events           http://127.0.0.1:19089/events"
echo
echo "   从 python3 log4shell/poc/01_probe.py 开始；自己先打，卡住再对答案。"
