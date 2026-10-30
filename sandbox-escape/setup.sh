#!/usr/bin/env bash
# =============================================================================
#  Sandbox Escape Lab —— 一键起靶场
# =============================================================================
#  用法：
#    ./setup.sh            起容器 + 铺 L6 的 flag
#    ./setup.sh --clean     清掉 L6 铺在宿主根目录的 flag 后退出
#
#  ⚠️ 这是「单独跑这个靶场」用的入口。整个 SecLab 已经把它并进去了，
#  日常请用仓库根目录的 ./lab.sh up（同样的容器、同样的端口，还会顺带
#  铺好 L6 的 flag）。两边都用 compose 的同一批容器名，别同时起。
#
#  注意 L6：它的 flag 必须放在「容器看不到、但宿主能看到」的位置，
#  所以脚本会往宿主根目录建一个 /lab-escape/ 目录。macOS / Windows 上
#  那是 Docker Desktop 的 Linux VM（不碰你的 macOS）；Linux 上是真宿主，
#  只多一个 /lab-escape 目录，--clean 可以删掉。
# =============================================================================

set -euo pipefail
cd "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

IMAGE="sec-lab/sandbox-escape:1.0"
HOST_DIR="/lab-escape"

# 把 flag 铺到宿主根目录：借一个「挂载了宿主 / 的一次性容器」来写，
# 这是唯一不依赖宿主机是不是 macOS 的写法。
plant_l6() {
    echo "[*] 铺设 L6 flag 到宿主 ${HOST_DIR}/l6.flag"
    docker run --rm \
        -v /:/host \
        -v "$PWD/flags/l6.flag:/src/l6.flag:ro" \
        --entrypoint sh "$IMAGE" -c \
        "mkdir -p /host${HOST_DIR} && cp /src/l6.flag /host${HOST_DIR}/l6.flag && chmod 644 /host${HOST_DIR}/l6.flag" \
        || { echo "[!] L6 flag 铺设失败（镜像还没构建？）"; return 1; }
    echo "[+] L6 flag 已就位"
}

if [ "${1:-}" = "--clean" ]; then
    docker run --rm -v /:/host --entrypoint sh "$IMAGE" -c "rm -rf /host${HOST_DIR}" 2>/dev/null \
        && echo "[+] 已删除宿主 ${HOST_DIR}"
    exit 0
fi

echo "[*] 构建并启动容器……"
# 跟 lab.sh 一样：默认构建器在写 ~/.docker 受限时会直接失败，
# 换成经典 builder 再试一次（代价是慢一点，但能过）
docker compose up -d --build \
    || DOCKER_BUILDKIT=0 docker compose up -d --build \
    || { echo "[x] 启动失败，看看上面的报错"; exit 1; }

# 等 web 真的起来（编译后的镜像启动很快，但别赌）
for _ in $(seq 1 30); do
    if curl -fsS -o /dev/null --max-time 2 http://127.0.0.1:8900/healthz 2>/dev/null; then
        break
    fi
    sleep 1
done

plant_l6 || true

cat <<'EOF'

────────────────────────────────────────────────────────────
  Sandbox Escape Lab
────────────────────────────────────────────────────────────
  L1~L4 页面    http://127.0.0.1:8900/
  L5 终端       docker exec -it sbox-sock bash
  L6 终端       docker exec -it sbox-priv bash

  一键验证 L1~L4 : python3 poc/verify.py
  答案           : ./lab.sh answer escape
────────────────────────────────────────────────────────────
EOF
