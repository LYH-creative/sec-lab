FROM php:8.1-apache

# 密钥目录必须禁止 Web 直接访问。
# 不挡的话 L3 能直接下走 rsa_private.pem、L4 能直接下走 default.key —— 关卡就废了。
# （顺手也是一课：密钥放在 web 根目录下本身就是个错误。）
RUN printf '<Directory /var/www/html/keys>\n    Require all denied\n</Directory>\n' \
        > /etc/apache2/conf-available/keys.conf \
    && a2enconf keys

# 教学环境，把 libxml / 各类警告都显示出来，方便对着报错看逻辑
RUN printf 'display_errors=On\nerror_reporting=E_ALL & ~E_DEPRECATED & ~E_NOTICE\n' \
    > /usr/local/etc/php/conf.d/zz-jwtlab.ini

WORKDIR /var/www/html
