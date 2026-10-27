#!/usr/bin/env bash
# DVWA 靶场管理脚本
# 用法: ./dvwa.sh <命令>
set -euo pipefail

# 切到脚本所在目录，保证 compose.yml 找得到
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$DIR"

case "${1:-status}" in
  up|start)
    docker compose up -d --wait
    echo "✅ 已启动，访问 http://127.0.0.1:8888  (admin / password)"
    ;;
  down|stop)
    docker compose down
    echo "🛑 已停止（数据保留，下次 up 直接接着用）"
    ;;
  restart)
    docker compose restart
    ;;
  status|ps)
    docker compose ps
    ;;
  logs)
    docker compose logs -f --tail=50
    ;;
  setup)
    # 首次部署 / 手动重建数据库后，用它一键建库
    /usr/bin/python3 setup_dvwa.py
    ;;
  reset)
    # 彻底重置：删容器 + 删数据卷 + 重建库（靶场被玩坏了用这个）
    docker compose down -v
    docker compose up -d --wait
    /usr/bin/python3 setup_dvwa.py
    ;;
  shell)
    docker exec -it dvwa bash
    ;;
  db)
    # 直接进数据库命令行
    docker exec -it dvwa-db mariadb -udvwa -pp@ssw0rd dvwa
    ;;
  *)
    echo "用法: $0 {up|down|restart|status|logs|setup|reset|shell|db}"
    echo "  up      启动靶场"
    echo "  down    停止靶场（保留数据）"
    echo "  restart 重启"
    echo "  status  查看状态"
    echo "  logs    实时看日志"
    echo "  setup   重建/初始化数据库"
    echo "  reset   彻底重置（清空所有数据后重建）"
    echo "  shell   进 web 容器"
    echo "  db      进数据库命令行"
    ;;
esac
