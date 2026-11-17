#!/usr/bin/env bash
# 铺 flag + 清理上一轮的痕迹。可重复执行。
set -euo pipefail

cd "$(dirname "$0")"

REDIS=redis-rce-redis
WEB=redis-rce-web

say()  { printf '\033[36m[*]\033[0m %s\n' "$*"; }
ok()   { printf '\033[32m[+]\033[0m %s\n' "$*"; }
warn() { printf '\033[33m[!]\033[0m %s\n' "$*"; }

# ---- 等 redis 起来 ---------------------------------------------------------
say "等 $REDIS 就绪"
for i in $(seq 1 30); do
  if docker exec "$REDIS" redis-cli -p 6379 ping >/dev/null 2>&1; then
    break
  fi
  sleep 1
done
docker exec "$REDIS" redis-cli -p 6379 ping >/dev/null 2>&1 \
  || { warn "$REDIS 没起来，先 docker compose -f compose.yml up -d --build"; exit 1; }

# ---- L1：flag 直接躺在 redis 里 -------------------------------------------
docker exec "$REDIS" redis-cli -p 6379 SET flag_l1 "$(tr -d '\n' < flags/l1.flag)" >/dev/null
ok "L1 flag 已写入 redis（key = flag_l1）"

# ---- L2：flag 在 web 容器根目录 --------------------------------------------
# compose 里已经用只读卷挂到 /flag_l2。挂载点上不能 docker cp
# （会报 device or resource busy），所以有挂载就直接跳过。
if docker exec "$WEB" test -f /flag_l2 2>/dev/null; then
  ok "L2 flag 已就位（compose 挂载）"
else
  docker cp flags/l2.flag "$WEB":/flag_l2 >/dev/null 2>&1 \
    && ok "L2 flag 已 cp 到 $WEB:/flag_l2" \
    || warn "L2 flag 没铺上，检查 redis-rce/flags/l2.flag"
fi

# ---- L3：flag 在 redis 容器根目录，只有 root 读得到 ------------------------
docker cp flags/l3.flag "$REDIS":/flag_l3 >/dev/null
docker exec "$REDIS" chmod 600 /flag_l3
docker exec "$REDIS" chown root:root /flag_l3
ok "L3 flag 已铺到 $REDIS:/flag_l3（600 root）"

# ---- 清理上一轮的产物，保证每次练习都是干净起点 ---------------------------
docker exec "$REDIS" rm -f /etc/crontabs/root 2>/dev/null || true
docker exec "$REDIS" redis-cli -p 6379 CONFIG SET dir /data >/dev/null 2>&1 || true
docker exec "$REDIS" redis-cli -p 6379 CONFIG SET dbfilename dump.rdb >/dev/null 2>&1 || true
docker exec "$REDIS" redis-cli -p 6379 DEL payload >/dev/null 2>&1 || true
docker exec "$REDIS" redis-cli -p 6379 DEL x >/dev/null 2>&1 || true
rm -f www/uploads/shell.php www/uploads/*.rdb 2>/dev/null || true

echo
WEB_PORT=$(docker port "$WEB" 80/tcp 2>/dev/null | head -1 | sed 's/.*://')
ok "就绪：redis 127.0.0.1:16379 · web http://127.0.0.1:${WEB_PORT:-8911}/"
echo "   从 poc/01_probe.py 开始；自己先打，卡住再对答案。"
