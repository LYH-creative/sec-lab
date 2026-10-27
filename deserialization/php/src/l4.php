<?php
/**
 * L4 —— phar：连 unserialize() 都不需要
 *
 * 这一关的页面里没有任何 unserialize()。
 * 危险发生在 @file_exists('phar://...') 解析归档元数据的那一刻。
 *
 * 目标：构造一个恶意 phar（可以伪装成 jpg），让它的 metadata 里的
 * Thumb 对象在解析时被"顺手"反序列化，__destruct 把 /flag 复制到 web 目录。
 */
require __DIR__ . '/inc/classes.php';

$file = $_GET['file'] ?? '';
$msg  = '';

// ---- 上传接口：只检查后缀，不检查内容 ----
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_FILES['img'])) {
    $name = basename($_FILES['img']['name']);
    if (preg_match('/\.(jpg|jpeg|png|gif)$/i', $name) && move_uploaded_file($_FILES['img']['tmp_name'], __DIR__ . '/uploads/' . $name)) {
        $msg = '上传成功：uploads/' . $name;
    } else {
        $msg = '只接受图片后缀';
    }
}
?><!doctype html>
<meta charset="utf-8">
<title>L4 · phar 反序列化</title>
<style>body{font:14px/1.7 -apple-system,Menlo,monospace;max-width:860px;margin:40px auto;padding:0 20px;color:#222}
pre{background:#f5f5f7;padding:12px;border-radius:6px;overflow:auto;white-space:pre-wrap;word-break:break-all}
code{background:#f0f0f3;padding:1px 5px;border-radius:3px}
.hint{color:#666;border-left:3px solid #ddd;padding-left:12px;margin:18px 0}
.warn{background:#fff4e5;border-left:3px solid #f0a020;padding:10px 14px;margin:14px 0}</style>

<h2>L4 · phar 反序列化</h2>
<?php if (version_compare(PHP_VERSION, '8.0', '>=')): ?>
<div class="warn">
  <b>当前是 PHP <?= PHP_VERSION ?>，本关的触发点在这里失效。</b><br>
  PHP 8.0 起 phar 元数据改成了<b>惰性反序列化</b>，<code>file_exists</code> / <code>is_file</code> /
  <code>file_get_contents</code> / <code>md5_file</code> 等文件函数都不再触发（实测验证过），
  只有显式访问 <code>Phar::getMetadata()</code> 才会。<br>
  请改用 PHP 7.4 端口练习：<a href="http://127.0.0.1:8891/l4.php">127.0.0.1:8891/l4.php</a>
</div>
<?php else: ?>
<div class="warn">
  <b>全站搜不到 unserialize</b>，但 phar:// 流在解析归档元数据时<b>内部</b>会做一次反序列化。
  当前 PHP <?= PHP_VERSION ?>：这是 PHP 7 时代的经典行为。
</div>
<?php endif; ?>
<div class="hint">
  <b>业务逻辑</b>：上传缩略图 → 用 <code>file_exists('phar://' + 文件名 + '/meta.txt')</code> 做归档完整性校验。<br>
  <b>你的目标</b>：让 <code>/flag</code> 出现在 <code>uploads/</code> 目录里，然后直接访问它。
</div>

<?php if ($msg): ?><p><b><?= htmlspecialchars($msg) ?></b></p><?php endif; ?>

<h3>1. 上传图片</h3>
<form method="post" enctype="multipart/form-data">
  <input type="file" name="img"> <button>上传</button>
</form>

<h3>2. 校验归档</h3>
<form method="get">
  <input name="file" value="<?= htmlspecialchars($file) ?>" style="width:100%;padding:8px;font-family:Menlo,monospace" placeholder="uploads/xxx.jpg">
  <button style="margin-top:8px;padding:6px 16px">校验</button>
</form>

<?php if ($file !== ''): ?>
  <h3>校验结果</h3>
  <pre><?php
    $path = 'phar://' . $file . '/meta.txt';
    echo htmlspecialchars($path) . "\n";
    echo @file_exists($path) ? '归档正常（metadata 已在解析时被反序列化）' : '归档损坏';
  ?></pre>
  <p>如果上面的操作成功了，去看看 <code><a href="uploads/">uploads/</a></code> 目录。</p>
<?php endif; ?>
