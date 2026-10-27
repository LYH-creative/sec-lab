<?php
/**
 * 对照页：修好了长什么样
 *
 * 把同一段恶意 XML 喂给「按正确姿势写的解析代码」，看看实体还会不会展开。
 *
 * 三层防线（强度从弱到强）：
 *   ① 加 LIBXML_NONET —— 只挡网络（外带、SSRF），file:// 照样读
 *   ② 不传 LIBXML_NOENT / LIBXML_DTDLOAD —— 实体不展开，但仍是「靠调用方记性」
 *   ③ 解析前直接拒绝 DOCTYPE —— 业务真不需要 DTD 时，这是最省事也最稳的
 *
 * 这里同时演示 ② 和 ③。注意看输出：实体没有被替换，而是原样留在文本里。
 */
header('Content-Type: text/html; charset=utf-8');

$xml    = $_POST['xml'] ?? '';
$strict = isset($_POST['reject_doctype']);
$out    = '';
$notice = '';

if ($xml !== '') {
    if ($strict && stripos($xml, '<!DOCTYPE') !== false) {
        $notice = '已拒绝：XML 中包含 DOCTYPE 声明';
    } else {
        libxml_use_internal_errors(true);
        libxml_clear_errors();

        // 关键：不传 LIBXML_NOENT（不替换实体）、不传 LIBXML_DTDLOAD（不加载外部 DTD）
        // 再补一个 LIBXML_NONET 兜底，禁止解析器发起任何网络请求
        $dom = new DOMDocument();
        if ($dom->loadXML($xml, LIBXML_NONET)) {
            $out = (string) $dom->textContent;
            if (trim($out) === '') {
                $out = '（文本为空 —— 外部实体没有被加载，这正是我们要的结果）';
            }
        } else {
            $e      = libxml_get_last_error();
            $notice = '解析失败：' . ($e ? trim($e->message) : '未知错误');
        }
    }
}
?>
<!doctype html>
<html lang="zh-CN">
<head><meta charset="utf-8"><title>安全写法对照</title><link rel="stylesheet" href="style.css"></head>
<body>
<a class="back" href="index.php">← 返回</a>
<h1>对照 · 安全写法</h1>
<p class="sub">
    L1~L5 的漏洞都在同一个地方：<code>loadXML($xml, LIBXML_NOENT | LIBXML_DTDLOAD)</code>。
    把这两个 flag 拿掉，XXE 就没了。
</p>
<div class="hint">
    想验证「拿掉 flag 真的有区别」的话，把 L1 的 payload 原样贴进来，
    再把 <code>LIBXML_NOENT</code> 加回去试一次 —— 你会看到 flag 重新出现。
</div>

<form method="post">
    <textarea name="xml" rows="8"><?= htmlspecialchars($xml) ?></textarea>
    <label style="display:block;margin-top:8px;font-size:13px">
        <input type="checkbox" name="reject_doctype" <?= $strict ? 'checked' : '' ?>> 额外开启：拒绝含 DOCTYPE 的 XML
    </label>
    <button>提交</button>
</form>

<?php if ($notice !== ''): ?>
    <div class="err"><?= htmlspecialchars($notice) ?></div>
<?php endif; ?>

<?php if ($out !== ''): ?>
    <div class="out"><pre><?= htmlspecialchars($out) ?></pre></div>
<?php endif; ?>
</body>
</html>
