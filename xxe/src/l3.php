<?php
/**
 * L3：报错型 XXE（本地 DTD）
 *
 * 业务设定：和 L2 一样不回显内容，但这一关额外假设服务器完全出不了网 ——
 *   L2 那套 OOB 外带在这里走不通（连不上你的服务器）。
 *
 * 那还能怎么把文件带出来？靠解析器自己的错误信息：
 *   1. 用 file:// 引入一个「本地 DTD」（真实环境里是系统或第三方库自带的 DTD，
 *      攻击者复用它们、劫持里面已经声明的实体）
 *   2. DTD 里先把 /flag 读进参数实体，再拿它拼一个「不存在的路径」
 *   3. libxml 试图加载那个路径时失败，错误信息里原样带上这个路径
 *   4. 本页故意没有关 display_errors，warning 就打到页面上了
 *
 * 注意一个规范级的限制（实测踩过）：
 *   XML 规范规定「内部子集」的实体声明值里不允许出现参数实体引用，
 *   libxml 会直接报 PEReferences forbidden in internal subset in Entity，
 *   整条链子直接不成立。所以 payload 必须把 DTD 放到外部（file:// 或 http://）。
 */
header('Content-Type: text/html; charset=utf-8');

$xml = $_POST['xml'] ?? '';

if ($xml !== '') {
    $dom = new DOMDocument();

    // 故意不调 libxml_use_internal_errors()：就是要让报错泄漏出去
    $dom->loadXML($xml, LIBXML_NOENT | LIBXML_DTDLOAD);
}
?>
<!doctype html>
<html lang="zh-CN">
<head><meta charset="utf-8"><title>L3 报错型</title><link rel="stylesheet" href="style.css"></head>
<body>
<a class="back" href="index.php">← 返回</a>
<h1>L3 · 盲打 · 报错型</h1>
<p class="sub">
    不回显内容，也不许出网。目标还是 <code>/flag</code>，只能靠报错把内容带出来。
</p>
<div class="hint">
    容器里放了一个「本地 DTD」：<code>/usr/share/xml/xxe-lab.dtd</code>（镜像自带，模拟系统 DTD）。<br>
    试试用 <code>file://</code> 把它引进来。
</div>
<div class="hint">
    踩坑提醒：把构造 payload 的那几句直接写进 <code>&lt;!DOCTYPE r [ ... ]&gt;</code> 内部子集是不行的。<br>
    XML 规范禁止在内部子集的实体声明值里引用参数实体，libxml 会报
    <code>PEReferences forbidden in internal subset</code>，链子根本搭不起来。
</div>

<form method="post">
    <textarea name="xml" rows="10"><?= htmlspecialchars($xml) ?></textarea>
    <button>提交</button>
</form>
</body>
</html>
