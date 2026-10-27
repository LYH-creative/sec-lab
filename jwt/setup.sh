#!/usr/bin/env bash
# 一键起靶场。首次 clone 后跑一次这个就行。
set -e
cd "$(dirname "$0")"

# 私钥要被容器里的 www-data 读，宿主机上是 600，得放宽
chmod 644 src/keys/rsa_private.pem src/keys/default.key src/pub.pem

docker compose up -d --build

echo
echo "JWT 靶场 L1~L4 + 修复对照 : http://127.0.0.1:8898/"
echo "一键验证四关            : python3 poc/jwt_exp.py"
