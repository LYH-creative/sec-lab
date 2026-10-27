<?php
require_once __DIR__ . '/jwt.php';

// 只有这一个普通账号。admin 的密码不给，flag 只能靠改 token 拿。
const USERS = [
    'alice' => ['pwd' => 'alice123', 'role' => 'user'],
];

// flag 在容器根目录，由 compose 挂进来
const FLAG_L1 = '/flag_l1';
const FLAG_L2 = '/flag_l2';
const FLAG_L3 = '/flag_l3';
const FLAG_L4 = '/flag_l4';

function read_flag(string $path): string
{
    return is_readable($path) ? trim((string)file_get_contents($path)) : '(flag 文件没挂进来)';
}

/**
 * 统一的页面头。$active 用来高亮当前关卡。
 * 逻辑全部在调用方写在这个函数之前完成 —— 因为 setcookie / header 必须早于任何输出。
 */
function page_head(string $title, string $active = ''): void
{
    $levels = [
        'l1' => ['l1.php', 'L1 弱密钥'],
        'l2' => ['l2.php', 'L2 alg:none'],
        'l3' => ['l3.php', 'L3 算法混淆'],
        'l4' => ['l4.php', 'L4 kid 注入'],
        'safe' => ['safe.php', '修复对照'],
    ];
    ?>
<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<title><?= htmlspecialchars($title) ?> · JWT 靶场</title>
<link rel="stylesheet" href="style.css">
</head>
<body>
<nav>
<?php foreach ($levels as $key => [$href, $label]): ?>
    <a href="<?= $href ?>"<?= $key === $active ? ' class="on"' : '' ?>><?= $label ?></a>
<?php endforeach; ?>
    <a href="index.php">首页</a>
</nav>
<h1><?= htmlspecialchars($title) ?></h1>
<?php
}

function page_foot(): void
{
    ?>
</body>
</html>
<?php
}

/** 把 token 摊开显示，方便对照三段结构 */
function render_token(string $token): void
{
    [$h, $p, $s] = jwt_parts($token);
    ?>
<div class="tok">
    <div class="seg h"><span>header</span><code><?= htmlspecialchars($h) ?></code></div>
    <div class="seg p"><span>payload</span><code><?= htmlspecialchars($p) ?></code></div>
    <div class="seg s"><span>signature</span><code><?= htmlspecialchars($s) ?></code></div>
</div>
<div class="decoded">
    <div><b>header</b> <code><?= htmlspecialchars(b64u_decode($h)) ?></code></div>
    <div><b>payload</b> <code><?= htmlspecialchars(b64u_decode($p)) ?></code></div>
</div>
<?php
}
