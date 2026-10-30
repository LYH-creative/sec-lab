# =============================================================================
#  L5 的「CI Runner」镜像：带 docker CLI 和 python3，手上还握着 docker.sock
# =============================================================================
#  这个容器模拟现实中很常见的一种配置：为了在容器里跑 CI / 自动部署，
#  图省事把宿主机的 /var/run/docker.sock 直接挂进来。
#  结果是容器内任意代码 = Docker 守护进程的完全控制权。
#
#  这里同时给 docker CLI（快速验证用）和 python3 + curl（手搓 Docker API 用），
#  后者才是这一关真正想让你理解的东西。
# =============================================================================

FROM docker:27-cli AS cli

FROM python:3.12-slim

COPY --from=cli /usr/local/bin/docker /usr/local/bin/docker

RUN apt-get update \
    && apt-get install -y --no-install-recommends curl ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /work
CMD ["sleep", "infinity"]
