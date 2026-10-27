#!/usr/bin/env bash
# 一键起靶场：建上传目录、给权限、构建并启动
set -euo pipefail
cd "$(dirname "$0")"

mkdir -p src/uploads
touch src/uploads/.gitkeep
# 容器里的 www-data 要往这里写文件，clone 下来默认是 755，必须放开
chmod 777 src/uploads

docker compose up -d --build

echo
echo "web      -> http://127.0.0.1:8895/"
echo "internal -> 不映射端口，只能在容器网络内访问（L4 的目标）"
