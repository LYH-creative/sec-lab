<?php
/**
 * L2 alg:none
 *
 * 病灶：服务端信任了令牌自己声明的签名算法。客户端说「这个 token 的 alg 是 none」，
 * 服务端就真的跳过验签了。
 *
 * 攻击路径：登录拿 token → 把 header 的 alg 改成 none → payload 的 role 改成 admin
 *           → 签名段清空（或整段删掉）→ 服务端直接放行。
 *
 * 这一关没有任何密码学难度，考的是「服务端该不该听客户端的话」。
 */
require __DIR__ . '/inc/common.php';

const SECRET = 'l2-this-one-is-not-bruteforceable-9f3a';

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
    $alg = jwt_header($token)['alg'] ?? 'HS256';
    [$h, $p, $s] = jwt_parts($token);

    if ($alg === 'none') {
        // ★ 漏洞点：无签名算法被当成「不需要验签」。
        $who = jwt_payload($token);
    } elseif (sign_hs256($h . '.' . $p, SECRET) === $s) {
        $who = jwt_payload($token);
    } elseif ($msg === '') {
        $msg = '签名校验失败';
    }
}

page_head('L2 · alg:none', 'l2');
?>
<p class="sub">
    同一个后台，但这次的密钥是随机长串，爆破这条路走不通。<br>
    注意服务端是从令牌里读 <code>alg</code> 的 —— 它凭什么相信你？
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
            管理员面板：<code><?= htmlspecialchars(read_flag(FLAG_L2)) ?></code>
        </div>
    <?php else: ?>
        <div class="hint">
            普通用户看不到 flag。<br>
            提示：JWT 规范里最早有一个 <code>alg: "none"</code>，意思是「无签名」。
            你猜这个服务端会不会认真对待它？
        </div>
    <?php endif; ?>
<?php endif; ?>

<?php page_foot(); ?>
