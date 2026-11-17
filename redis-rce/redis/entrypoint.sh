#!/bin/sh
set -e

# busybox crond，后台跑。alpine 里 crontab 目录是 /etc/crontabs
# （标准 Linux 是 /var/spool/cron/crontabs，busybox 把它改短了）。
crond -b -l 8

# L3 的 flag：从只读挂载复制到根目录，再收紧成 600 root。
# 不直接 chmod 挂载文件 —— bind mount 上去改权限会连带改宿主机文件，
# git 里会多出 mode 变更的噪音。
if [ -f /flags/l3.flag ]; then
  cp /flags/l3.flag /flag_l3
  chmod 600 /flag_l3
fi

# L1 的 flag 是 redis 里的数据（不是文件），等 server 起来再灌。
# 放后台，不阻塞下面的 exec。
(
  sleep 1
  redis-cli -p 6379 SET flag_l1 "$(cat /flags/l1.flag 2>/dev/null)" >/dev/null 2>&1
) &

echo "[*] redis-rce: busybox crond 已启动，redis-server 以 $(id -un) 身份运行"
exec redis-server /etc/redis/redis.conf
