#!/usr/bin/env bash
# =============================================================================
#  一键启动 log4shell 靶场（构建 + 启动 + 初始化）
# =============================================================================
#
#  本机实测：默认 buildx 会报
#     failed to update builder last activity time: ... operation not permitted
#  和根 lab.sh 里记的是同一个问题（~/.docker/buildx 不可写）。
#  这里按同样顺序做三级回退，免得每次手动拼 BUILDX_CONFIG。
# =============================================================================
set -euo pipefail
cd "$(dirname "$0")"

say() { printf '\033[36m[*]\033[0m %s\n' "$*"; }

up() { docker compose -f compose.yml up -d --build "$@"; }

if up; then
    :
else
    cfg="$(mktemp -d)/buildx"
    say "默认构建器失败，改用临时 buildx 状态目录重试"
    if BUILDX_CONFIG="$cfg" up; then
        :
    else
        say "仍失败，退回经典 builder"
        DOCKER_BUILDKIT=0 up
    fi
fi

./setup.sh
