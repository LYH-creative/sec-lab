#!/usr/bin/env bash
# =============================================================================
#  SecLab 统一管理脚本
# =============================================================================
#  用法：
#     ./lab.sh up              启动全部 Web 靶场（不含 ARP）
#     ./lab.sh up all          连 ARP 一起启动（需要额外构建网络实验镜像）
#     ./lab.sh down            停止全部容器（保留数据）
#     ./lab.sh restart         重启
#     ./lab.sh status          查看容器与端口
#     ./lab.sh logs [服务名]   跟踪日志
#     ./lab.sh shell <服务名>  进容器
#     ./lab.sh init            只做初始化（铺 flag / 修权限 / 灌数据）
#     ./lab.sh reset           彻底重置（删容器和数据库卷后重建）
#     ./lab.sh answer [靶场]   打印答案速查
#     ./lab.sh build           只构建镜像
#
#  兼容 /bin/bash 3.2（macOS 自带），不使用 bash4 特性。
# =============================================================================

set -euo pipefail

cd "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(pwd)"

# ---- 颜色（不支持时自动降级为空串）------------------------------------------
if [ -t 1 ]; then
    C_OK=$'\033[32m'; C_ERR=$'\033[31m'; C_WARN=$'\033[33m'
    C_DIM=$'\033[2m'; C_B=$'\033[1m'; C_0=$'\033[0m'
else
    C_OK=''; C_ERR=''; C_WARN=''; C_DIM=''; C_B=''; C_0=''
fi

info()  { printf '%s[*]%s %s\n' "$C_DIM" "$C_0" "$*"; }
ok()    { printf '%s[+]%s %s\n' "$C_OK" "$C_0" "$*"; }
warn()  { printf '%s[!]%s %s\n' "$C_WARN" "$C_0" "$*"; }
die()   { printf '%s[x]%s %s\n' "$C_ERR" "$C_0" "$*" >&2; exit 1; }

DC="docker compose"

# =============================================================================
#  环境检查
# =============================================================================
preflight() {
    command -v docker >/dev/null 2>&1 \
        || die "找不到 docker。先装 Docker Desktop / Docker Engine。"

    docker info >/dev/null 2>&1 \
        || die "Docker 守护进程没在跑。macOS / Windows 先打开 Docker Desktop，Linux 执行 sudo systemctl start docker。"

    $DC version >/dev/null 2>&1 \
        || die "docker compose（v2 插件）不可用。它跟 Docker Desktop 一起装；Linux 上需要 docker-compose-plugin。"
}

# =============================================================================
#  清理同名历史容器
#  这些容器名是固定的，以前用「单靶场模式」（进子目录 docker compose up）
#  起过的话会残留同名容器，导致集成版直接报 container name is already in use。
#  只删不属于本项目（sec-lab）的同名容器，数据卷不动。
# =============================================================================
ALL_CONTAINERS="lab-portal dvwa dvwa-db deser-php deser-php74 deser-java
xxe-web xxe-internal gopher-web gopher-legacy-public gopher-legacy-internal
gopher-redis gopher-db gopher-fpm jwt-web webshell-hunt
arp-gw arp-victim arp-attacker"

cleanup_conflicts() {
    local n proj
    for n in $ALL_CONTAINERS; do
        docker container inspect "$n" >/dev/null 2>&1 || continue
        proj=$(docker inspect -f '{{index .Config.Labels "com.docker.compose.project"}}' "$n" 2>/dev/null || true)
        [ "$proj" = "sec-lab" ] && continue
        warn "发现同名历史容器 $n（旧项目：${proj:-手动创建}），清理后重建"
        docker rm -f "$n" >/dev/null 2>&1 || true
    done

    # 旧项目的网络也要清：ARP 靶场固定用 172.28.0.0/24（脚本里 IP 写死），
    # 遗留网络占着这个网段会报 "Pool overlaps with other one on this address space"。
    for n in arp-lab_arpnet arp-lab_default deserialization_default dvwa_default \
             jwt_default xxe_default webshell-hunt_default gopher_default; do
        docker network inspect "$n" >/dev/null 2>&1 || continue
        docker network rm "$n" >/dev/null 2>&1 \
            && warn "清理遗留网络 $n（占用固定网段）"
    done
}

# =============================================================================
#  准备：目录权限 + 铺 flag
#  这些必须在容器启动前做完 —— 有的是 bind mount 的只读内容，
#  有的要让容器内的 www-data / redis 用户有写权限。
# =============================================================================
prepare() {
    info "准备目录与 flag……"

    # 三个靶场有上传目录，容器内的 www-data / redis 要往里写
    for d in deserialization/php/src/uploads gopher/src/uploads xxe/src/uploads; do
        mkdir -p "$d"
        touch "$d/.gitkeep"
        chmod 777 "$d" 2>/dev/null || warn "chmod 777 $d 失败，L4/上传类关卡可能写不进去"
    done

    # JWT：宿主机上私钥是 600，bind mount 进去后 www-data 读不到，
    # openssl_sign 会静默签出空签名。这里统一放宽。
    if [ -d jwt/src/keys ]; then
        chmod 644 jwt/src/keys/*.pem jwt/src/keys/*.key jwt/src/pub.pem 2>/dev/null || true
    fi

    # gopher 的两个 gopher 实例是只读挂载，flag 必须在 up 之前就位
    cp -f gopher/flags/l1.flag gopher/legacy/public/l1.txt
    cp -f gopher/flags/l2.flag gopher/legacy/internal/l2.txt

    ok "目录与 flag 就绪"
}

# =============================================================================
#  等待工具：轮询而不是 sleep 固定秒数，慢机器上也不会误判
# =============================================================================
wait_tcp() {  # $1=host $2=port $3=描述 $4=超时秒
    local host="$1" port="$2" desc="$3" limit="${4:-90}" i=0
    printf '%s[*]%s 等待 %s ' "$C_DIM" "$C_0" "$desc"
    while [ "$i" -lt "$limit" ]; do
        if (echo > "/dev/tcp/$host/$port") >/dev/null 2>&1; then
            printf ' %sok%s\n' "$C_OK" "$C_0"; return 0
        fi
        printf '.'; sleep 1; i=$((i + 1))
    done
    printf ' %s超时%s\n' "$C_WARN" "$C_0"; return 1
}

wait_http() {  # $1=url $2=描述 $3=超时秒
    local url="$1" desc="$2" limit="${3:-90}" i=0
    printf '%s[*]%s 等待 %s ' "$C_DIM" "$C_0" "$desc"
    while [ "$i" -lt "$limit" ]; do
        if curl -fsS -o /dev/null --max-time 3 "$url" 2>/dev/null; then
            printf ' %sok%s\n' "$C_OK" "$C_0"; return 0
        fi
        printf '.'; sleep 1; i=$((i + 1))
    done
    printf ' %s超时%s\n' "$C_WARN" "$C_0"; return 1
}

# =============================================================================
#  灌数据：容器起来之后才能做的初始化
# =============================================================================
seed() {
    # ---- 1. gopher L5：MySQL 里的 flag ------------------------------------
    # 不能用 mariadb-admin ping 探测：初始化没结束时它也能连上，
    # 那时 root 密码还没落库，插数据会 Access denied。
    local i=0 ready=0
    printf '%s[*]%s 等待 gopher-db 完成初始化 ' "$C_DIM" "$C_0"
    while [ "$i" -lt 90 ]; do
        if docker exec gopher-db mariadb -uroot -proot123 -e 'SELECT 1' >/dev/null 2>&1; then
            ready=1; break
        fi
        printf '.'; sleep 1; i=$((i + 1))
    done
    printf '\n'

    if [ "$ready" -eq 1 ]; then
        docker exec -i gopher-db mariadb -uroot -proot123 secret >/dev/null 2>&1 <<SQL || warn "gopher L5 灌数据失败"
DELETE FROM flag WHERE id = 1;
INSERT INTO flag (id, val) VALUES (1, '$(tr -d '\n' < gopher/flags/l5.flag)');
SQL
        ok "gopher L5 flag 已写入 MySQL"
    else
        warn "gopher-db 未就绪，L5 的 flag 没灌进去。稍后重跑 ./lab.sh init"
    fi

    # ---- 2. gopher L3：Redis 里的 flag ------------------------------------
    if docker exec gopher-redis redis-cli SET l3_flag "$(tr -d '\n' < gopher/flags/l3.flag)" >/dev/null 2>&1; then
        ok "gopher L3 flag 已写入 Redis"
    else
        warn "gopher-redis 未就绪，L3 的 flag 没灌进去"
    fi

    # ---- 3. DVWA 建库 ------------------------------------------------------
    # 官方镜像不自动建表，正常流程是打开 /setup.php 点一下按钮。这里自动化。
    if wait_http "http://127.0.0.1:8888/login.php" "DVWA web" 60; then
        if command -v python3 >/dev/null 2>&1; then
            if python3 dvwa/setup_dvwa.py http://127.0.0.1:8888 >/dev/null 2>&1; then
                ok "DVWA 数据库已初始化"
            else
                warn "DVWA 自动建库失败，手动打开 http://127.0.0.1:8888/setup.php 点一下按钮"
            fi
        else
            warn "没有 python3，DVWA 需手动打开 http://127.0.0.1:8888/setup.php 点一下按钮"
        fi
    fi
}

# =============================================================================
#  启动
# =============================================================================
cmd_up() {
    local scope="${1:-web}"
    preflight
    cleanup_conflicts
    prepare

    local profile_args=""
    if [ "$scope" = "all" ]; then
        profile_args="--profile net"
        info "包含 ARP 靶场（首次需要构建网络实验镜像，约 1~2 分钟）"
    fi

    info "构建并启动容器（首次需要拉镜像 + 构建，视网络 5~10 分钟）……"
    # shellcheck disable=SC2086
    if ! $DC $profile_args up -d --build; then
        warn "默认构建器失败，改用经典 builder 重试一次（常见于 buildx 写 ~/.docker 受限）"
        # shellcheck disable=SC2086
        DOCKER_BUILDKIT=0 $DC $profile_args up -d --build \
            || die "启动失败。跑 ./lab.sh logs 看具体报错。"
    fi

    echo
    seed
    echo
    print_banner "$scope"
}

print_banner() {
    local scope="${1:-web}"
    echo "────────────────────────────────────────────────────────────"
    printf '  %s靶场入口%s\n' "$C_B" "$C_0"
    echo "────────────────────────────────────────────────────────────"
    printf '  导航页        http://127.0.0.1:8880/\n'
    printf '  DVWA          http://127.0.0.1:8888/        %sadmin / password%s\n' "$C_DIM" "$C_0"
    printf '  反序列化      http://127.0.0.1:8890/        %sPHP 8.1 · L1~L3%s\n' "$C_DIM" "$C_0"
    printf '                http://127.0.0.1:8891/        %sPHP 7.4 · L4 phar%s\n' "$C_DIM" "$C_0"
    printf '                http://127.0.0.1:8892/        %sJava CC6%s\n' "$C_DIM" "$C_0"
    printf '  XXE           http://127.0.0.1:8895/\n'
    printf '  Gopher SSRF   http://127.0.0.1:8896/        %s另有 gopher://127.0.0.1:7070%s\n' "$C_DIM" "$C_0"
    printf '  JWT           http://127.0.0.1:8898/        %salice / alice123%s\n' "$C_DIM" "$C_0"
    printf '  webshell-hunt http://127.0.0.1:8899/        %sdocker exec -it webshell-hunt bash%s\n' "$C_DIM" "$C_0"
    if [ "$scope" = "all" ]; then
        printf '  ARP           终端实验，见 %sarp/README.md%s\n' "$C_DIM" "$C_0"
    else
        printf '  ARP           未启动（网络层实验）→ %s./lab.sh up all%s\n' "$C_DIM" "$C_0"
    fi
    echo "────────────────────────────────────────────────────────────"
    printf '  答案速查：%s./lab.sh answer%s      停止：%s./lab.sh down%s\n' "$C_DIM" "$C_0" "$C_DIM" "$C_0"
    echo
}

# =============================================================================
#  其余命令
# =============================================================================
cmd_down() {
    preflight
    local profile_args="--profile net"
    # shellcheck disable=SC2086
    $DC $profile_args down
    ok "已停止（数据保留，下次 up 接着用）"
}

cmd_status() {
    preflight
    $DC --profile net ps --format 'table {{.Service}}\t{{.Status}}\t{{.Ports}}' 2>/dev/null \
        || $DC ps
    echo
    info "宿主机监听端口："
    if command -v lsof >/dev/null 2>&1; then
        lsof -nP -iTCP -sTCP:LISTEN 2>/dev/null \
            | awk 'NR==1 || /:(8880|8888|8890|8891|8892|8895|8896|8898|8899|7070)$/' \
            | sed 's/^/    /' || true
    fi
}

cmd_logs() {
    preflight
    if [ $# -gt 0 ]; then
        $DC logs -f --tail=80 "$1"
    else
        $DC logs -f --tail=40
    fi
}

cmd_shell() {
    preflight
    [ $# -ge 1 ] || die "用法：./lab.sh shell <服务名>  （如 webshell-hunt / jwt-web / dvwa）"
    docker exec -it "$1" bash 2>/dev/null \
        || docker exec -it "$1" sh
}

cmd_build() {
    preflight
    prepare
    info "只构建镜像……"
    if ! $DC --profile net build; then
        warn "改用经典 builder 重试"
        DOCKER_BUILDKIT=0 $DC --profile net build || die "构建失败"
    fi
    ok "构建完成"
}

cmd_init() {
    preflight
    prepare
    seed
    ok "初始化完成"
}

cmd_reset() {
    preflight
    warn "这会删除容器、数据库数据卷，以及各靶场 uploads 里的练习产物。"
    printf '  确认重置？输入 yes 继续：'
    read -r ans
    [ "$ans" = "yes" ] || { info "已取消"; exit 0; }

    info "清理容器与数据卷……"
    $DC --profile net down -v --remove-orphans

    # bind mount 的上传目录不会被 down -v 清掉，手动清
    for d in deserialization/php/src/uploads gopher/src/uploads xxe/src/uploads; do
        [ -d "$d" ] || continue
        find "$d" -mindepth 1 ! -name '.gitkeep' -delete 2>/dev/null || true
    done

    cmd_up all
}

cmd_answer() {
    local f="$ROOT/docs/answers.md"
    [ -f "$f" ] || die "找不到 $f"

    if [ $# -lt 1 ]; then
        # 没指定靶场：只打印最上面的 flag 汇总表
        awk '/^## 一、flag 总表/{f=1} f&&/^## /&&!/flag 总表/{exit} f' "$f"
        echo
        info "看某一关的完整思路：./lab.sh answer <dvwa|deser|xxe|gopher|jwt|hunt|arp>"
        return 0
    fi

    local pat="$1"
    case "$pat" in
        deser|deserialization|反序列化) pat="反序列化" ;;
        xx*|XX*)                        pat="XXE" ;;
        gopher|ssrf|Gopher)             pat="Gopher" ;;
        jwt|JWT)                        pat="JWT" ;;
        hunt|webshell|webshell-hunt)    pat="webshell-hunt" ;;
        arp|ARP)                        pat="ARP" ;;
        dvwa|DVWA)                      pat="DVWA" ;;
    esac

    # 注意：BSD awk（macOS 自带）不支持 IGNORECASE，用 tolower 代替
    awk -v pat="$pat" '
        /^## / { if (hit) exit; if (index(tolower($0), tolower(pat))) hit = 1 }
        hit
    ' "$f"
}

# =============================================================================
#  入口
# =============================================================================
case "${1:-help}" in
    up)      shift; cmd_up "${1:-web}" ;;
    down|stop)  cmd_down ;;
    restart) preflight; $DC --profile net restart; ok "已重启" ;;
    status|ps)  cmd_status ;;
    logs)    shift; cmd_logs "$@" ;;
    shell)   shift; cmd_shell "$@" ;;
    init)    cmd_init ;;
    reset)   cmd_reset ;;
    answer|ans) shift; cmd_answer "$@" ;;
    build)   cmd_build ;;
    help|-h|--help)
        sed -n '3,20p' "$0" | sed 's/^#//; s/^ //'
        ;;
    *)
        die "未知命令：$1。跑 ./lab.sh help 看用法。"
        ;;
esac
