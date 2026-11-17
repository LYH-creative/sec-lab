# =============================================================================
#  Log4Shell 靶场 · 被攻击的应用（一个容器里跑三个不同配置的 JVM）
# =============================================================================
#
#  三个进程共用同一份 Main.class，差别只在 classpath 和 JVM 参数：
#    8080  log4j 2.14.1 + trustURLCodebase=true   → 能加载远程 codebase，完整 RCE
#    8081  log4j 2.14.1 + JDK 默认(false)         → 有 JNDI 回连，但远程类被拒
#    8082  log4j 2.17.1 + JDK 默认(false)         → lookup 被移除，连回连都没有
#
#  关于 trustURLCodebase：JDK 8u191 / 11.0.1 之后默认禁止 JNDI 从远程
#  codebase 加载类。现在能拉到的 eclipse-temurin:8-jdk 都远新于 8u191，
#  所以想复现 2021 年那种「一个 User-Agent 直接 RCE」，必须显式把开关打开。
#  这不是作弊，是在还原当年的 JDK 环境；8081 保留默认值专门用来对照。
#
#  jar 不塞进仓库（沿用本仓库 deserialization/java 的约定），构建时从
#  Maven Central 拉，失败自动退阿里云镜像。
# =============================================================================

FROM eclipse-temurin:8-jdk

RUN set -eu; \
    mkdir -p /app/lib /app/classes /app/conf; \
    for v in 2.14.1 2.17.1; do \
      for a in log4j-api log4j-core; do \
        f="/app/lib/$a-$v.jar"; \
        curl -fsSL --retry 3 -o "$f" \
          "https://repo1.maven.org/maven2/org/apache/logging/log4j/$a/$v/$a-$v.jar" \
        || curl -fsSL --retry 3 -o "$f" \
          "https://maven.aliyun.com/repository/public/org/apache/logging/log4j/$a/$v/$a-$v.jar"; \
      done; \
    done

COPY Main.java /app/Main.java
COPY conf/log4j2.xml /app/conf/log4j2.xml

# log4j-api 是编译期依赖；core 只在运行时需要。
# 编译产物和 log4j2.xml 一起进 classpath，配置才会被读到。
RUN javac -encoding UTF-8 -cp /app/lib/log4j-api-2.14.1.jar \
        -d /app/classes /app/Main.java

COPY start.sh /app/start.sh
RUN chmod +x /app/start.sh

EXPOSE 8080 8081 8082
CMD ["/app/start.sh"]
