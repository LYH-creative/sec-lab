#!/usr/bin/env bash
# 一键重建靶场：解依赖 → 编译 → 起一个全新的目标容器。
# 每次执行都会拿到「未注入」的干净状态，可重复跑。
# 端口只绑 127.0.0.1，classes / libs 都以只读方式挂进容器。
set -euo pipefail
BASE="$(cd "$(dirname "$0")" && pwd)"
cd "$BASE"

if [ ! -f libs/tomcat-embed-core-9.0.46.jar ]; then
  echo "[*] 从 sec-lab/shiro:1.0 镜像提取 Spring Boot / Tomcat 依赖 ..."
  docker rm -f memshell-deps >/dev/null 2>&1 || true
  docker create --name memshell-deps sec-lab/shiro:1.0 >/dev/null
  docker cp memshell-deps:/app/shiro-1.2.4.jar "$BASE/.shiro-lab.jar" >/dev/null
  docker rm memshell-deps >/dev/null
  mkdir -p libs .unpack
  unzip -q -o "$BASE/.shiro-lab.jar" 'BOOT-INF/lib/*' -d "$BASE/.unpack"
  cp "$BASE/.unpack"/BOOT-INF/lib/*.jar libs/
  rm -rf "$BASE/.unpack" "$BASE/.shiro-lab.jar"
fi

echo "[*] 编译目标侧应用（--release 8，宿主 javac 17 编出的 class 必须降到 52）..."
mkdir -p classes attacker
javac --release 8 -cp "libs/*" -d classes src/lab/MemShellLab.java src/lab/MemShellInject.java
javac --release 8 -cp "libs/*" -d attacker src/evil/EvilFilter.java

echo "[*] 启动目标容器 ..."
docker rm -f memshell-lab >/dev/null 2>&1 || true
docker run -d --name memshell-lab \
  -p 127.0.0.1:19090:8080 \
  -v "$BASE/classes:/app/classes:ro" \
  -v "$BASE/libs:/app/libs:ro" \
  -v "$BASE/start.sh:/app/start.sh:ro" \
  -w /app eclipse-temurin:8-jdk sh /app/start.sh >/dev/null

for i in $(seq 1 40); do
  if curl -sf --max-time 1 http://127.0.0.1:19090/ >/dev/null 2>&1; then
    echo "[+] 就绪（${i}s）：http://127.0.0.1:19090/"
    echo "    目标侧：JDK 8 + Tomcat 9.0.46 + Spring Boot 2.3.12，/app 只读"
    echo "    攻击者侧：attacker/evil/EvilFilter.class（不挂载进容器）"
    exit 0
  fi
  sleep 1
done
echo "[!] 启动超时，看日志：docker logs memshell-lab" >&2
exit 1
