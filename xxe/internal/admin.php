<?php
/**
 * 内网管理接口（L4 的目标）
 *
 * 它自己没有任何鉴权 —— 靠的是「外面访问不到」这层网络隔离。
 * 代码里保留了一个来源 IP 检查，用来演示经典的内网信任假设：
 * 只要是内网地址来的就放行。
 *
 * 于是 XXE 一旦能让 web 容器去请求它，来源就是容器内网 IP，检查直接通过。
 */
header('Content-Type: text/plain; charset=utf-8');

$ip = $_SERVER['REMOTE_ADDR'] ?? '';
$isPrivate = (bool) preg_match('/^(10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.)/', $ip);

if (!$isPrivate) {
    http_response_code(403);
    echo "forbidden: 只允许内网调用（来源 {$ip}）\n";
    exit;
}

echo file_get_contents('/flag');
