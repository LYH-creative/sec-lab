<?php
$levels = [
    ['l1.php', 'L1 弱密钥', 'HS256 密钥是弱口令，离线爆破后自己签发', 'l1'],
    ['l2.php', 'L2 alg:none', '服务端信任令牌自带的 alg，改成 none 直接绕过验签', 'l2'],
    ['l3.php', 'L3 算法混淆', 'RS256 的公钥被当成 HS256 的密钥用', 'l3'],
    ['l4.php', 'L4 kid 注入', 'kid 拼进文件路径，路径穿越读到空密钥', 'l4'],
    ['safe.php', '对照：修好了长什么样', '把造出来的令牌喂给正确写法，看它怎么全拒掉', 'safe'],
];
?>
<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<title>JWT 靶场</title>
<link rel="stylesheet" href="style.css">
</head>
<body>
<h1>JWT 靶场</h1>
<p class="sub">
    同一套「后台管理系统」被打穿四次，每次只改一个实现细节。<br>
    四个 flag 分别在容器的 <code>/flag_l1</code> ~ <code>/flag_l4</code>，
    都要求你拿出 <code>role=admin</code> 的令牌。<br>
    唯一能登录的账号：<code>alice / alice123</code>（普通用户）。
</p>

<ul class="levels">
<?php foreach ($levels as [$href, $title, $desc, $cls]): ?>
    <li class="<?= $cls ?>">
        <a href="<?= $href ?>"><?= $title ?></a>
        <span><?= $desc ?></span>
    </li>
<?php endforeach; ?>
</ul>

<p class="sub">
    一键验证：<code>python3 poc/jwt_exp.py</code>（纯标准库，四关全打）
</p>
</body>
</html>
