#!/usr/bin/env bash
# 单独启动 replay-adcs 靶场。
# 集成编排请用仓库根目录的 ./lab.sh up，别两边同时起（容器名会冲突）。
set -e
cd "$(dirname "$0")"

docker compose up -d --build

echo
echo "Replay / AD CS 五关   : http://127.0.0.1:8910/"
echo "一键验证              : python3 poc/exp.py"
echo "只跑某一关            : python3 poc/exp.py --only L4"
echo "协议层自测            : python3 ntlm.py"
echo
echo "不想开 Docker 也行： LAB_PORT=8910 python3 server.py"
