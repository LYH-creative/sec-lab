#!/usr/bin/env bash
# ARP 欺骗靶场 —— 一键起环境
# 用法：./run.sh
# 停止：docker compose down
set -euo pipefail
cd "$(dirname "$0")"

if ! docker info >/dev/null 2>&1; then
    echo "[!] Docker 没在跑，先打开 Docker Desktop"
    exit 1
fi

echo "[*] 构建镜像（首次约 1~2 分钟，装 scapy 和 dsniff）……"
# 用经典 builder：BuildKit 在部分环境会因写 ~/.docker 权限失败
DOCKER_BUILDKIT=0 docker build -t arp-lab:latest . >/dev/null

echo "[*] 启动容器……"
docker compose up -d >/dev/null
sleep 2

echo
echo "=== 拓扑 ==="
docker ps --filter name=arp- --format '  {{.Names}}\t{{.Status}}'
echo
echo "  victim   (172.28.0.3) ── 被欺骗的一方，默认路由指向 172.28.0.2"
echo "  gateway  (172.28.0.2) ── 扮演网关 + 上游网站"
echo "  attacker (172.28.0.4) ── 攻击机，ARP 毒化 + 抓包"
echo
echo "  真实 MAC（每次重建容器都会变，脚本里不要写死）："
printf "    gateway  %s\n" "$(docker exec arp-gw cat /sys/class/net/eth0/address)"
printf "    victim   %s\n" "$(docker exec arp-victim cat /sys/class/net/eth0/address)"
printf "    attacker %s\n" "$(docker exec arp-attacker cat /sys/class/net/eth0/address)"
echo
echo "接下来的实验步骤见 README.md"
