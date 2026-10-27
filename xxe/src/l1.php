<?php
/**
 * L1：基础 XXE（有回显）
 *
 * 业务设定：商品导入接口。前端提交一段 <order> XML，服务端把结果打印出来确认。
 *
 * 漏洞点：simplexml_load_string() 的第三个参数带了 LIBXML_NOENT。
 *   这个标志的意思是「把实体引用替换成实体的真实内容」。
 *   如果实体的 SYSTEM 指向 file:///flag，文件内容就会变成 XML 文本的一部分，
 *   而页面又把解析结果原样打印出来 —— 文件就这么被读走了。
 *
 * 没有 LIBXML_NOENT 的话，实体不会被展开，页面上只会看到 &xxe; 这几个字符。
 */
header('Content-Type: text/html; charset=utf-8');

$sample = <<<'XML'
<?xml version="1.0" encoding="UTF-8"?>
<order>
  <item>机械键盘</item>
  <qty>2</qty>
</order>
XML;

$xml    = $_POST['xml'] ?? '';
$result = '';
$error  = '';

// 调试记录：把收到的原始内容落一份，方便排查「为什么没回显」
if ($xml !== '') {
    @file_put_contents(
        '/tmp/xxe_req.log',
        date('H:i:s') . ' len=' . strlen($xml) . "\n" . $xml . "\n---\n",
        FILE_APPEND
    );
}

if ($xml !== '') {
    libxml_use_internal_errors(true);
    libxml_clear_errors();

    $sx = simplexml_load_string($xml, 'SimpleXMLElement', LIBXML_NOENT | LIBXML_DTDLOAD);

    if ($sx === false) {
        $e     = libxml_get_last_error();
        $error = $e ? trim($e->message) : '未知解析错误';
    } else {
        // (string)$sx 只取根节点的「直属文本」，子节点里的内容拿不到，所以按业务遍历一层
        foreach ($sx->children() as $child) {
            $result .= $child->getName() . ': ' . trim((string) $child) . "\n";
        }
    }
}
?>
<!doctype html>
<html lang="zh-CN">
<head><meta charset="utf-8"><title>L1 商品导入</title><link rel="stylesheet" href="style.css"></head>
<body>
<a class="back" href="index.php">← 返回</a>
<h1>L1 · 商品导入（有回显）</h1>
<p class="sub">目标：读到容器里的 <code>/flag</code>。</p>

<form method="post">
    <textarea name="xml" rows="10"><?= htmlspecialchars($xml !== '' ? $xml : $sample) ?></textarea>
    <button>提交</button>
</form>

<?php if ($error !== ''): ?>
    <div class="err">解析失败：<?= htmlspecialchars($error) ?></div>
<?php endif; ?>

<?php if ($result !== ''): ?>
    <div class="out"><pre><?= htmlspecialchars($result) ?></pre></div>
<?php endif; ?>
</body>
</html>
