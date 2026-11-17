FROM redis:7-alpine

# bash：/dev/tcp 是 bash 扩展，alpine 默认只有 ash，不支持
# busybox 自带 crond，不用额外装 cron
RUN apk add --no-cache bash

COPY redis.conf /etc/redis/redis.conf
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

# 覆盖官方 entrypoint：不让它把 redis-server 降权到 redis 用户。
# L2 要写 /var/www/html，L3 要写 /etc/crontabs，都得 root。
ENTRYPOINT ["/entrypoint.sh"]
