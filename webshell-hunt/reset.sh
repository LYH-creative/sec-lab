#!/usr/bin/env bash
# 重置靶场：重新构建镜像并拉起容器。
# 所有后门的权限位、时间戳都在 Dockerfile 里固定，重建即可回到初始状态。
set -euo pipefail
cd "$(dirname "$0")"

# 用传统 builder，避免 buildx 在某些环境下写 ~/.docker 失败
export DOCKER_BUILDKIT=0

docker compose down -v 2>/dev/null || true
docker compose build --no-cache
docker compose up -d

echo
echo "靶场已启动: http://127.0.0.1:8899/"
echo "进入容器:   docker exec -it webshell-hunt bash"
