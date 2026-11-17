# =============================================================================
#  Log4Shell 靶场 · 攻击者基础设施（LDAP + HTTP codebase + 事件收集）
# =============================================================================
#
#  第一阶段用 JDK 8 把两个"恶意类"编译成 class 文件版本 52，
#  这样 8 系列的 JVM 才加载得了（宿主是 javac 17，直接编出来是 61，会炸）。
#  第二阶段只带 python:3.12-slim，server.py 全部用标准库，不装任何包。
#
#  server.py 同时干三件事：
#    1389/tcp  极简 LDAP 服务，返回 javaNamingReference 指向远程 codebase
#    8000/tcp  托管 .class，并提供 /events /reset 给 poc 查结果
# =============================================================================

FROM eclipse-temurin:8-jdk AS javac
COPY exploit/ /src/
RUN mkdir -p /out && javac -encoding UTF-8 -d /out /src/L2.java /src/L3.java

FROM python:3.12-slim
COPY --from=javac /out/ /serve/
COPY server.py /app/server.py

EXPOSE 1389 8000
CMD ["python3", "-u", "/app/server.py"]
