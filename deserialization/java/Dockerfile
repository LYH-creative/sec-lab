FROM eclipse-temurin:8-jdk

ARG FLAG="FLAG{java_deser_cc6_9f1c}"
RUN printf '%s\n' "${FLAG}" > /flag && chmod 644 /flag
RUN mkdir -p /tmp/out /app/classes /app/lib && chmod 777 /tmp/out

WORKDIR /app
COPY server/ /app/server/
COPY poc/ /app/poc/

# commons-collections 3.1：构建时从 Maven Central 拉，不把第三方 jar 塞进仓库
RUN curl -fsSL --retry 3 -o /app/lib/commons-collections-3.1.jar \
        https://repo1.maven.org/maven2/commons-collections/commons-collections/3.1/commons-collections-3.1.jar

RUN javac -encoding UTF-8 -cp /app/lib/commons-collections-3.1.jar -d /app/classes \
        /app/server/DeserServer.java /app/poc/Cc6Gen.java

EXPOSE 8080
CMD ["java", "-cp", "/app/classes:/app/lib/commons-collections-3.1.jar", "DeserServer"]
