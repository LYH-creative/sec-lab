#!/bin/sh
# =============================================================================
#  一个容器、三个 JVM，靠 classpath 和 JVM 参数拉开差别
# =============================================================================
#
#  8080  L1~L3：log4j 2.14.1，显式打开 trustURLCodebase，模拟 2021 年的 JDK
#  8081  L4-1 ：log4j 2.14.1，JDK 保持默认（新版默认禁止远程 codebase）
#  8082  L4-2 ：log4j 2.17.1，已修复版本，lookup 不再解析 jndi
#
#  L1 的 flag 放在环境变量里，是为了能用 ${env:FLAG_L1} 这个 lookup 外带。
#  真实环境里这也是 Log4Shell 最常被忽略的危害：不 RCE 也能读环境变量。
# =============================================================================
set -eu

FLAG_L1="$(cat /flag_l1)"
export FLAG_L1

CP="/app/classes:/app/conf"
VULN="/app/lib/log4j-api-2.14.1.jar:/app/lib/log4j-core-2.14.1.jar"
FIXED="/app/lib/log4j-api-2.17.1.jar:/app/lib/log4j-core-2.17.1.jar"

java -Dcom.sun.jndi.ldap.object.trustURLCodebase=true \
     -cp "$CP:$VULN" Main 8080 filter vuln-2.14.1-trustURLCodebase-true &

java -cp "$CP:$VULN" Main 8081 nofilter jdk-hardened-2.14.1 &

java -cp "$CP:$FIXED" Main 8082 nofilter patched-2.17.1 &

# 任何一个子进程退出就整体退出，方便 docker logs 看到是谁挂了
wait -n 2>/dev/null || wait
