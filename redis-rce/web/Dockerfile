FROM php:8.1-apache

# 开 mod_rewrite 用不上，但保留目录索引方便直接看 uploads 里落了什么
RUN a2enmod headers >/dev/null 2>&1 || true

WORKDIR /var/www/html
