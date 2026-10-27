<?php
$levels = [
    ['l1.php', 'L1 基础 XXE（有回显）', '订单导入接口，解析结果直接打印在页面上', 'l1'],
    ['l2.php', 'L2 盲打 XXE（无回显）', '只返回「成功 / 失败」，没有回显 —— 只能把数据外带出去', 'l2'],
    ['l3.php', 'L3 报错型 XXE', '不回显也不许出网，靠 parser 的报错信息把内容漏出来', 'l3'],
    ['l4.php', 'L4 XXE → SSRF', '拉取远程 XML 解析；内网服务只在容器网络里可达', 'l4'],
    ['l5.php', 'L5 上传 SVG 触发的 XXE', '头像上传，校验只看后缀名', 'l5'],
    ['safe.php', '对照：修好了长什么样', '同样一段恶意 XML，喂给修复后的解析代码', 'safe'],
];
?>
<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<title>XXE 靶场</title>
<link rel="stylesheet" href="style.css">
</head>
<body>
<h1>XXE 靶场</h1>
<p class="sub">
    所有关卡的 flag 都在容器的 <code>/flag</code>。五关是递进的：<br>
    会回显 → 不回显 → 不出网 → 打内网 → 传文件。
</p>

<ul class="levels">
<?php foreach ($levels as [$href, $title, $desc, $cls]): ?>
    <li class="<?= $cls ?>">
        <a href="<?= $href ?>"><?= $title ?></a>
        <span><?= $desc ?></span>
    </li>
<?php endforeach; ?>
</ul>

<p class="sub">盲打关需要一个能接收外带数据的 HTTP 服务，本地跑：<code>python3 poc/oob_server.py</code></p>
</body>
</html>
