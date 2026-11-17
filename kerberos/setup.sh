#!/bin/sh
# 启动 Kerberos 黄金 / 白银票据靶场。仅绑定 127.0.0.1，不对外暴露。
set -e
cd "$(dirname "$0")"

docker compose up -d

printf '等待服务就绪'
i=0
while [ "$i" -lt 30 ]; do
  if curl -sf http://127.0.0.1:8907/api/state >/dev/null 2>&1; then
    break
  fi
  printf '.'
  i=$((i + 1))
  sleep 1
done
printf '\n'

if ! curl -sf http://127.0.0.1:8907/api/state >/dev/null 2>&1; then
  echo "[失败] 服务未就绪，查看日志：docker compose logs -f"
  exit 1
fi

echo "[OK] 面板：http://127.0.0.1:8907"
echo "[OK] 命令帮助：python3 poc/lab.py help"
echo "[OK] 一键通关：python3 poc/solve.py"
echo "[OK] 停止：docker compose down"
