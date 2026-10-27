<?php
/**
 * L5：文件上传形态的 XXE（SVG）
 *
 * 业务设定：头像上传。允许 svg/png/jpg，服务端为了「生成预览」，会把 SVG 读一遍取文字。
 *
 * 漏洞点有两层：
 *   1. 校验只看后缀名，没有检查内容到底是什么；
 *   2. SVG 本身就是 XML 文档，里面完全可以塞 DOCTYPE 和实体。
 *
 * 为什么这关值得单独练：很多上传点只防「上传 php 然后访问」，不防「上传 xml 然后被解析」。
 * 文件放在 uploads/ 下，看起来只是一张图，解析的时候照样触发 XXE。
 */
header('Content-Type: text/html; charset=utf-8');

$msg     = '';
$preview = '';
$ok      = false;

if (!empty($_FILES['avatar'])) {
    $f    = $_FILES['avatar'];
    $name = basename($f['name']);
    $ext  = strtolower(pathinfo($name, PATHINFO_EXTENSION));

    if (!in_array($ext, ['svg', 'png', 'jpg', 'jpeg'], true)) {
        $msg = '只允许 svg / png / jpg';
    } elseif (!is_dir(__DIR__ . '/uploads')) {
        $msg = 'uploads 目录不存在，先跑 ./setup.sh';
    } else {
        $dst = __DIR__ . '/uploads/' . $name;
        if (move_uploaded_file($f['tmp_name'], $dst)) {
            $msg = '上传成功：uploads/' . htmlspecialchars($name);

            // 服务端解析图片内容（就是这里踩雷）
            libxml_use_internal_errors(true);
            $dom = new DOMDocument();
            if ($dom->loadXML(file_get_contents($dst), LIBXML_NOENT | LIBXML_DTDLOAD)) {
                $preview = (string) $dom->textContent;
                $ok      = true;
            } else {
                $preview = '（无法当作 SVG 解析，可能不是 XML）';
            }
        } else {
            $msg = '保存失败，检查 uploads 目录权限';
        }
    }
}
?>
<!doctype html>
<html lang="zh-CN">
<head><meta charset="utf-8"><title>L5 头像上传</title><link rel="stylesheet" href="style.css"></head>
<body>
<a class="back" href="index.php">← 返回</a>
<h1>L5 · 头像上传（SVG）</h1>
<p class="sub">目标：传一个「图片」，让服务端解析它的时候把 <code>/flag</code> 读出来。</p>

<form method="post" enctype="multipart/form-data">
    <input type="file" name="avatar">
    <button>上传</button>
</form>

<?php if ($msg !== ''): ?>
    <div class="<?= $ok ? 'ok' : 'err' ?>"><?= $msg ?></div>
<?php endif; ?>

<?php if ($preview !== ''): ?>
    <h2>预览文本</h2>
    <div class="out"><pre><?= htmlspecialchars($preview) ?></pre></div>
<?php endif; ?>
</body>
</html>
