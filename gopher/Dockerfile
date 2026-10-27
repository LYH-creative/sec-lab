FROM php:8.1-apache

# 靶场需要看清响应内容，把错误全打出来（真实环境不该这么配）
RUN printf 'display_errors=On\nerror_reporting=E_ALL & ~E_DEPRECATED & ~E_NOTICE\n' \
    > /usr/local/etc/php/conf.d/zz-gopher-lab.ini

# L4 的落点：redis 通过 CONFIG SET dir 写进来的 webshell 会出现在这里
RUN mkdir -p /var/www/html/uploads && chmod 777 /var/www/html/uploads

WORKDIR /var/www/html
