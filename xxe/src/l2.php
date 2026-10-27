<?php
/**
 * L2：盲打 XXE（无回显）
 *
 * 业务设定：日志上报接口。服务端解析 XML 后只入库，不回显任何内容 ——
 *   页面上永远只有「已接收」或「格式错误」两种情况。
 *
 * 和 L1 的唯一区别：不打印解析结果。
 *   这时候你没法直接从响应里读文件，必须让服务器主动把数据送出来（OOB）：
 *   在 XML 里引入一个攻击者服务器上的外部 DTD，DTD 里把 /flag 的内容拼进一个 URL，
 *   解析器读到那个实体就会去请求那个 URL —— 数据就落在你的日志里了。
 *
 * 本关故意不往任何可读的地方写内容，就是要逼你走外带这条路。
 */
header('Content-Type: text/html; charset=utf-8');

$xml    = $_POST['xml'] ?? '';
$status = '';

if ($xml !== '') {
    libxml_use_internal_errors(true);
    libxml_clear_errors();

    $dom = new DOMDocument();
    $ok  = $dom->loadXML($xml, LIBXML_NOENT | LIBXML_DTDLOAD);

    // 只告诉调用方成没成功，内容一个字都不吐
    $status = $ok ? '已接收' : '格式错误';
}
?>
<!doctype html>
<html lang="zh-CN">
<head><meta charset="utf-8"><title>L2 日志上报</title><link rel="stylesheet" href="style.css"></head>
<body>
<a class="back" href="index.php">← 返回</a>
<h1>L2 · 日志上报（盲打）</h1>
<p class="sub">
    这一关没有回显。目标文件是 <code>/flag_blind</code>。<br>
    先在本机跑 <code>python3 poc/oob_server.py</code>，再让它去请求你服务器上的 DTD。
</p>
<div class="hint">
    盲打的三件套：外部 DTD（<code>%remote;</code>）→ 参数实体里再定义实体（<code>%eval;</code>）→ 触发外带（<code>%exfil;</code>）。<br>
    直接写 <code>SYSTEM "http://你的地址/?d=%file;"</code> 是不行的，实体引用不能直接嵌在另一个实体的 SYSTEM 字面量里。
</div>
<div class="hint">
    <code>/flag_blind</code> 里的内容是<strong>没有花括号</strong>的，这是故意的：<br>
    libxml 会校验 URI，<code>{</code> <code>}</code> 属于非法字符，带上去会直接报
    <code>Invalid URI</code>，请求压根发不出去 —— 盲打最常见的第一个坑。
</div>

<form method="post">
    <textarea name="xml" rows="10" placeholder="&lt;?xml version=&quot;1.0&quot;?&gt; ..."><?= htmlspecialchars($xml) ?></textarea>
    <button>上报</button>
</form>

<?php if ($status !== ''): ?>
    <div class="<?= $status === '已接收' ? 'ok' : 'err' ?>"><?= htmlspecialchars($status) ?></div>
<?php endif; ?>
</body>
</html>
