FROM php:8.1-fpm

# L6 的教学前提：默认 allow_url_include=Off，
# 真实场景要配合任意文件写入才能把 auto_prepend_file 指到可执行内容上。
# 这里直接开，把注意力集中在「拼 FastCGI 包」本身。
RUN printf 'allow_url_include=On\n' > /usr/local/etc/php/conf.d/zz-gopher-lab.ini

# 默认的 zz-docker.conf 里写的是 listen = 9000，
# php-fpm 会把裸端口解析成 [::]:9000（只监听 IPv6），
# 从别的容器用 IPv4 连过来会直接 RST —— 靶场里必须显式绑 0.0.0.0。
RUN printf '[www]\nlisten = 0.0.0.0:9000\n' > /usr/local/etc/php-fpm.d/zz-lab.conf

WORKDIR /var/www/html
