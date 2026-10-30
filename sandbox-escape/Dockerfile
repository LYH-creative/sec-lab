# =============================================================================
#  Sandbox Escape Lab —— 主镜像（web 服务 + 四个语言级沙箱）
# =============================================================================
#  为什么是「python 镜像 + 借一个 node 二进制」，而不是装两个运行时：
#    整个靶场只需要 node 解释器本身（L1 的 runner 只用内置 vm / fs，
#    没有 node_modules），所以把 node:20-slim 里的静态一点儿的二进制
#    复制过来就够了，比 apt 装 nodejs 快得多，镜像也小。
#    node 20 是在 bookworm 上编译的，跑在 trixie 的 python:3.12-slim 上
#    只要 glibc 不小于编译时的版本就没问题（新版跑老二进制）。
#
#  注意：容器里所有东西都以 root 跑（L4 的 chroot 需要 CAP_SYS_CHROOT）。
#  这在真实世界里是严重错误配置，在本靶场里是故意留的入口。
# =============================================================================

FROM node:20-slim AS nodebin

FROM python:3.12-slim

COPY --from=nodebin /usr/local/bin/node /usr/local/bin/node

WORKDIR /app

# 关卡代码不 COPY 进来，靠 compose 把 ./src 挂到 /app，
# 改完页面刷新就生效，不用重建镜像。这里只准备 chroot 用的空目录兜底。
RUN mkdir -p /jail/data && printf '你被关在 /jail 里。\n' > /jail/readme.txt

EXPOSE 8900

CMD ["python3", "-u", "/app/server.py"]
