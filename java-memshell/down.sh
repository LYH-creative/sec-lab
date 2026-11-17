#!/usr/bin/env bash
# 停止并删除目标容器。不会删除 libs / classes / attacker（重建时可直接复用）。
docker rm -f memshell-lab
