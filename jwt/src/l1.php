<?php
/**
 * L1 弱密钥
 *
 * 病灶：HS256 的密钥是人拍的，运维图省事设成 "secret"。
 * 攻击路径：登录拿一个合法 token → 离线爆破出密钥 → 用真密钥签一个 role=admin 的 token。
 *
 * 这一关考的其实是「HMAC 密钥强度」，不是 JWT 本身 —— 但它是最常被打穿的一关。
 */
require __DIR__ . '/inc/common.php';

const SECRET = 'secret';

$msg = '';
$token = $_COOKIE['token'] ?? '';
$who = null;

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['username'])) {
    $name = (string)$_POST['username'];
    $pass = (string)$_POST['password'];

    if (isset(USERS[$name]) && hash_equals(USERS[$name]['pwd'], $pass)) {
        $header = b64u(json_encode(['alg' => 'HS256', 'typ' => 'JWT']));
        $payload = b64u(json_encode([
            'sub' => $name,
            'role' => USERS[$name]['role'],
            'iat' => time(),
            'exp' => time() + 3600,
        ]));
        $token = $header . '.' . $payload . '.' . sign_hs256($header . '.' . $payload, SECRET);
        setcookie('token', $token, ['path' => '/', 'httponly' => false]);
    } else {
        $msg = '用户名或密码错误';
    }
}

if ($token !== '') {
    [$h, $p, $s] = jwt_parts($token);
    // 教学简化：用 === 比较。真实代码应 hash_equals()，防时序侧信道。
    if (sign_hs256($h . '.' . $p, SECRET) === $s) {
        $who = jwt_payload($token);
    } elseif ($msg === '') {
        $msg = '签名校验失败';
    }
}

page_head('L1 · 弱密钥', 'l1');
?>
<p class="sub">后台管理系统的登录入口。用 <code>alice / alice123</code> 登进来，看看你的令牌里写了什么。</p>

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
            管理员面板：<code><?= htmlspecialchars(read_flag(FLAG_L1)) ?></code>
        </div>
    <?php else: ?>
        <div class="hint">
            普通用户看不到 flag。flag 在 <code>role=admin</code> 的令牌下面。<br>
            提示：这套系统的 JWT 密钥是运维随手设的，长度 5~6 字符，大概率就躺在 rockyou 前 100 行里。
        </div>
    <?php endif; ?>
<?php endif; ?>

<?php page_foot(); ?>
