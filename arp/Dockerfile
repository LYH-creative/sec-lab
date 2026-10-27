# ARP 欺骗靶场 —— 三容器共用镜像
# 一个镜像同时充当 网关 / 受害者 / 攻击机，省得维护三份环境
# 关键依赖只有两组：
#   - dsniff    → 提供 arpspoof 命令行工具（业界最常用的现成工具）
#   - scapy     → 手工构造 ARP 包的 Python 库（用来理解原理）
FROM python:3.12-slim

ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONUNBUFFERED=1

# 工具清单逐个说明：
#   dsniff          arpspoof 命令
#   iproute2        ip 命令（改路由、看 ARP 缓存 ip neigh）
#   iputils-ping    ping
#   tcpdump         抓包（验证流量真的经过攻击机）
#   net-tools       arp / ifconfig 老命令，查看 arp 表时比 ip neigh 直观
#   curl            受害者发起 HTTP 请求
#   procps          ps 等
#   netcat-openbsd  起个临时监听端口做连通性测试
#   iptables        关闭转发/做 NAT 的实验
RUN apt-get update && apt-get install -y --no-install-recommends \
        dsniff \
        iproute2 \
        iputils-ping \
        tcpdump \
        net-tools \
        curl \
        procps \
        netcat-openbsd \
        iptables \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# scapy 用 pip 装最新版即可；这个镜像是 arm64（Apple Silicon），pip 会装 aarch64 wheel
RUN pip install --no-cache-dir scapy

WORKDIR /lab

# 默认空跑，具体角色由 compose 里的 command 决定
CMD ["sleep", "infinity"]
