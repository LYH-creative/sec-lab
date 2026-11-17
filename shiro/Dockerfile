# =============================================================================
#  Shiro 多版本靶场
# =============================================================================
#  构建阶段做的事：
#    用同一个 Maven 工程，改 -Dshiro.version 打六次包，得到
#      1.2.4  —— Shiro-550（硬编码默认密钥）
#      1.2.5  —— Shiro-721（密钥随机，但 CBC 没有完整性校验）
#      1.4.2  —— 路径绕过：四个 CVE 全中
#      1.5.2  —— 修了 1957
#      1.6.0  —— 修了 13933
#      1.7.1  —— 修了 17523
#    然后在运行时用 --lab.mode + --server.port 决定每个进程扮演谁。
#
#  基础镜像用 temurin 8：CC6 gadget 在 JDK 8 上最省事，而且 2020 年那批
#  Shiro 漏洞的真实环境就是 JDK 8 + Spring Boot 2.3。
# =============================================================================

FROM maven:3.9-eclipse-temurin-8 AS build

# 国内拉 Maven Central 经常卡，用阿里云镜像兜一层。
# 用 COPY 而不是 heredoc：legacy builder（DOCKER_BUILDKIT=0）里
# RUN 内的 heredoc 不会被展开，settings.xml 会变成空文件。
COPY settings.xml /root/.m2/settings.xml

WORKDIR /build

# 先只拷贝 pom 拉依赖，源码改动不会让这层缓存失效
COPY app/pom.xml /build/pom.xml
RUN mvn -q -B dependency:go-offline -Dshiro.version=1.2.4 || true

COPY app/src /build/src

# 六个版本依次打包。第二次开始本地仓库已有 Spring Boot 依赖，快很多。
RUN mkdir -p /dist \
 && for v in 1.2.4 1.2.5 1.4.2 1.5.2 1.6.0 1.7.1; do \
      echo "=== build shiro ${v} ==="; \
      mvn -q -B clean package -DskipTests -Dshiro.version=${v} || exit 1; \
      cp /build/target/shiro-lab.jar /dist/shiro-${v}.jar || exit 1; \
    done \
 && ls -lh /dist


FROM eclipse-temurin:8-jdk

# /tmp/out 是 550 的"回显目录"：payload 把 /flag 复制进来，再从 HTTP 取
RUN mkdir -p /app/payloads /tmp/out && chmod 777 /tmp/out

WORKDIR /app
COPY --from=build /dist/ /app/

EXPOSE 8080

# 默认起 550；compose 里会按需覆盖成 721 或 bypass 的多进程
CMD ["java", "-jar", "/app/shiro-1.2.4.jar", "--lab.mode=550", "--lab.version=1.2.4"]
