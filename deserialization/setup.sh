#!/usr/bin/env bash
# 一键起靶场。首次 clone 后跑一次这个就行。
set -e
cd "$(dirname "$0")"

# L4 要把文件写进 uploads，容器里的 www-data 需要写权限
mkdir -p php/src/uploads
chmod 777 php/src/uploads

docker compose up -d --build

echo
echo "PHP 8.1  L1~L3 : http://127.0.0.1:8890/"
echo "PHP 7.4  L4    : http://127.0.0.1:8891/l4.php"
echo "Java     CC6   : http://127.0.0.1:8892/"
