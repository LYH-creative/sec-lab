<?php
/**
 * L4：XXE → SSRF
 *
 * 业务设定：数据源导入。用户填一个 URL，服务端把这个 URL 拉回来当 XML 解析。
 *   为了防止被拿去读本地文件，代码做了「协议白名单」：只允许 http/https。
 *
 * 为什么没用：白名单管住的是你填的那个 URL，管不住 XML *里面* 的实体。
 *   攻击者让 URL 指向自己的服务器，返回一份带 XXE 的 XML，
 *   实体再指向内网地址 —— 解析器照样会去请求内网，跟协议白名单毫无关系。
 *
 * 本关目标：拿到内网服务 xxe-internal 的 flag。
 *   宿主机上是访问不到它的（compose 里没映射端口），只有容器网络里能通。
 */
header('Content-Type: text/html; charset=utf-8');

$url    = $_POST['url'] ?? '';
$raw    = $_POST['xml'] ?? '';   // 调试用：也可以直接贴一段 XML，跳过「拉远程」这一步
$result = '';
$error  = '';

$payload = '';

if ($url !== '') {
    if (!preg_match('#^https?://#i', $url)) {
        $error = '只允许 http(s) 地址';
    } else {
        $payload = @file_get_contents($url);
        if ($payload === false) {
            $error = '拉取失败：' . $url;
        }
    }
} elseif ($raw !== '') {
    $payload = $raw;
}

if ($payload !== '') {
    libxml_use_internal_errors(true);
    libxml_clear_errors();

    $dom = new DOMDocument();
    if ($dom->loadXML($payload, LIBXML_NOENT | LIBXML_DTDLOAD)) {
        $result = (string) $dom->textContent;
    } else {
        $e     = libxml_get_last_error();
        $error = $e ? trim($e->message) : '解析失败';
    }
}
?>
<!doctype html>
<html lang="zh-CN">
<head><meta charset="utf-8"><title>L4 数据源导入</title><link rel="stylesheet" href="style.css"></head>
<body>
<a class="back" href="index.php">← 返回</a>
<h1>L4 · 数据源导入（XXE → SSRF）</h1>
<p class="sub">
    目标：内网服务 <code>http://internal/admin.php</code>。
    你在宿主机上 curl 不到它 —— 试试就知道了，DNS 都不解析。
</p>

<form method="post">
    <p class="sub">远程数据源地址：</p>
    <input type="text" name="url" value="<?= htmlspecialchars($url) ?>" placeholder="https://example.com/feed.xml">
    <p class="sub" style="margin-top:14px">或者直接贴一段 XML：</p>
    <textarea name="xml" rows="6" placeholder="&lt;?xml version=&quot;1.0&quot;?&gt; ..."><?= htmlspecialchars($raw) ?></textarea>
    <button>导入</button>
</form>

<?php if ($error !== ''): ?>
    <div class="err"><?= htmlspecialchars($error) ?></div>
<?php endif; ?>

<?php if ($result !== ''): ?>
    <div class="out"><pre><?= htmlspecialchars($result) ?></pre></div>
<?php endif; ?>
</body>
</html>
