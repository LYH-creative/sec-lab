#!/usr/bin/env bash
# =============================================================================
#  Shiro 靶场一键启动
# =============================================================================
#  六个 Shiro 版本共用一个镜像，镜像构建时会把 1.2.4 / 1.2.5 / 1.4.2 /
#  1.5.2 / 1.6.0 / 1.7.1 全部打包进去（第一次构建要从 Maven 拉依赖，大概
#  5~8 分钟；settings.xml 里已配阿里云镜像。之后有层缓存，改代码重构建 2 分钟左右）。
# =============================================================================
set -euo pipefail
cd "$(dirname "$0")"

# buildx 在某些环境（受限工作目录、容器里跑）写不了 ~/.docker/buildx，
# 会报 "failed to update builder last activity time ... operation not permitted"。
# 顺序：默认 → 临时 BUILDX_CONFIG → 经典 builder（慢，但一定能跑）。
if ! docker compose -f compose.yml up -d --build 2>/dev/null; then
    echo "[*] 默认构建器失败，改用临时 buildx 状态目录重试"
    if ! BUILDX_CONFIG="$(mktemp -d)/buildx" \
         docker compose -f compose.yml up -d --build 2>/dev/null; then
        echo "[*] 退回经典 builder（这一步会比较慢，且可能长时间无输出）"
        DOCKER_BUILDKIT=0 docker compose -f compose.yml up -d --build
    fi
fi

echo
echo "  550 默认密钥        http://127.0.0.1:8901/"
echo "  721 padding oracle  http://127.0.0.1:8902/"
echo "  路径绕过 1.4.2      http://127.0.0.1:8903/"
echo "  路径绕过 1.5.2      http://127.0.0.1:8904/"
echo "  路径绕过 1.6.0      http://127.0.0.1:8905/"
echo "  路径绕过 1.7.1      http://127.0.0.1:8906/"
echo
echo "  验证脚本："
echo "    python3 poc/shiro550_exp.py"
echo "    python3 poc/shiro721_exp.py"
echo "    python3 poc/bypass_exp.py"
