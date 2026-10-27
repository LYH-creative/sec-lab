FROM php:8.1-apache

# L3（报错型 XXE）靠的就是 PHP 把 libxml 的解析警告打印到页面上，
# 所以这里把 display_errors 打开。生产环境当然不该开 —— 这本身就是个信息泄露放大器。
RUN printf 'display_errors=On\nerror_reporting=E_ALL & ~E_DEPRECATED & ~E_NOTICE\n' \
    > /usr/local/etc/php/conf.d/zz-xxe.ini

# L3 要用的「本地 DTD」：模拟系统/第三方库自带的 DTD 文件
COPY dtd/xxe-lab.dtd /usr/share/xml/xxe-lab.dtd

# 上传目录要允许 www-data 写入（bind mount 会盖掉镜像里的目录，setup.sh 里还会再建一次）
RUN mkdir -p /var/www/html/uploads && chmod 777 /var/www/html/uploads

WORKDIR /var/www/html
