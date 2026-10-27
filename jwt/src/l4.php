<?php
/**
 * L4 kid 注入（路径穿越 → 空密钥）
 *
 * 病灶：kid（Key ID）是令牌里客户端可控的字符串，服务端直接拿它拼文件路径。
 *
 * 攻击路径：把 kid 改成 ../../../../dev/null → 读到空文件 → 空字符串当 HMAC 密钥
 *           → 攻击者用同样的空密钥签 admin 令牌，签名自然对得上。
 *
 * /var/www/html/keys/../../../../dev/null 规范化后就是 /dev/null。
 * 为什么用 dev/null 而不是别的可读文件：它内容为空、一定存在、一定可读，
 * 而空字符串恰好是 hash_hmac 能接受的合法密钥 —— 完美踩中。
 */
require __DIR__ . '/inc/common.php';

$msg = '';
$token = $_COOKIE['token'] ?? '';
$who = null;

/** 正常的系统密钥，存在 keys/default.key */
function default_key(): string
{
    return trim((string)@file_get_contents(__DIR__ . '/keys/default.key'));
}

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['username'])) {
    $name = (string)$_POST['username'];
    $pass = (string)$_POST['password'];

    if (isset(USERS[$name]) && hash_equals(USERS[$name]['pwd'], $pass)) {
        $header = b64u(json_encode(['alg' => 'HS256', 'typ' => 'JWT', 'kid' => 'default']));
        $payload = b64u(json_encode([
            'sub' => $name,
            'role' => USERS[$name]['role'],
            'iat' => time(),
            'exp' => time() + 3600,
        ]));
        $input = $header . '.' . $payload;
        $token = $input . '.' . sign_hs256($input, default_key());
        setcookie('token', $token, ['path' => '/', 'httponly' => false]);
    } else {
        $msg = '用户名或密码错误';
    }
}

if ($token !== '') {
    [$h, $p, $s] = jwt_parts($token);
    $input = $h . '.' . $p;

    // ★ 漏洞点：kid 完全由客户端提供，直接拼进路径。
    $kid = (string)(jwt_header($token)['kid'] ?? 'default');
    $keyfile = __DIR__ . '/keys/' . $kid;
    $key = @file_get_contents($keyfile);

    if ($key === false) {
        if ($msg === '') {
            $msg = "找不到 kid 对应的密钥：{$kid}";
        }
    } elseif (hash_equals(sign_hs256($input, $key), $s)) {
        $who = jwt_payload($token);
    } elseif ($msg === '') {
        $msg = '签名校验失败';
    }
}

page_head('L4 · kid 注入', 'l4');
?>
<p class="sub">
    支持多租户之后，密钥不再写死在代码里，而是按 <code>kid</code>（Key ID）去
    <code>keys/</code> 目录下取对应的密钥文件。<br>
    目录里现在只有一个 <code>default.key</code>。
</p>

<?php if ($msg): ?><div class="err"><?= htmlspecialchars($msg) ?></div><?php endif; ?>

<?php if ($who === null): ?>
    <form method="post">
        <input type="text" name="username" placeholder="用户名" value="alice">
        <input type="password" name="password" placeholder="密码">
        <button type="submit">登录</button>
    </form>
<?php else: ?>
    <div class="ok">
        已登录：<b><?= htmlspecialchars($who['sub'] ?? '?') ?></b> ，
        角色 <code><?= htmlspecialchars($who['role'] ?? '?') ?></code>
    </div>

    <h2>你的令牌</h2>
    <?php render_token($token); ?>

    <?php if (($who['role'] ?? '') === 'admin'): ?>
        <div class="ok">
            管理员面板：<code><?= htmlspecialchars(read_flag(FLAG_L4)) ?></code>
        </div>
    <?php else: ?>
        <div class="hint">
            普通用户看不到 flag。<br>
            提示：<code>kid</code> 是个字符串，它被拼进了一个文件路径。
            如果让它往上爬几层，会读到什么？
        </div>
    <?php endif; ?>
<?php endif; ?>

<?php page_foot(); ?>
