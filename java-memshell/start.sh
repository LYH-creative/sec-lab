#!/bin/sh
# 目标侧启动脚本：所有类都从普通 classpath 加载，不用 fat jar / Maven。
# JVM 会自动展开 /app/libs/* 这个通配符。
exec java -cp "/app/classes:/app/libs/*" lab.MemShellLab
