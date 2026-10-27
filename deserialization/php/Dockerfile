ARG PHP_BASE=8.1
FROM php:${PHP_BASE}-apache

# 靶场 flag
ARG FLAG="FLAG{php_deser_default}"
RUN printf '%s\n' "${FLAG}" > /flag && chmod 644 /flag

# L1 的 rm -rf 目标目录
RUN mkdir -p /tmp/cache && chmod 777 /tmp/cache

# 开发用：把错误都显示出来，方便观察魔术方法的调用
RUN printf 'display_errors=On\nerror_reporting=E_ALL\n' > /usr/local/etc/php/conf.d/zz-dev.ini

COPY src/ /var/www/html/
RUN mkdir -p /var/www/html/uploads && chown -R www-data:www-data /var/www/html

EXPOSE 80
