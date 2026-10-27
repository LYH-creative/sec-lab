<?php
/**
 * L3 算法混淆（RS256 → HS256）
 *
 * 病灶：验证函数按令牌里的 alg 分支选算法，而 HS256 分支是拿「公钥文件的内容」当 HMAC 密钥。
 *
 * 为什么这能打通：RS256 用私钥签、公钥验，公钥本来就是公开的（这页就能下载）。
 * 一旦服务端愿意用同一份公钥去做 HMAC，攻击者手里就有了一把可以自己签名的「密钥」。
 *
 * 攻击路径：下载 pub.pem → 把 header 的 alg 改成 HS256 → 用 pub.pem 的字节当密钥签 HS256。
 */
require __DIR__ . '/inc/common.php';

const PRIV = __DIR__ . '/keys/rsa_private.pem';
const PUB = __DIR__ . '/pub.pem';

$msg = '';
$token = $_COOKIE['token'] ?? '';
$who = null;

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['username'])) {
    $name = (string)$_POST['username'];
    $pass = (string)$_POST['password'];

    if (isset(USERS[$name]) && hash_equals(USERS[$name]['pwd'], $pass)) {
        $header = b64u(json_encode(['alg' => 'RS256', 'typ' => 'JWT']));
        $payload = b64u(json_encode([
            'sub' => $name,
            'role' => USERS[$name]['role'],
            'iat' => time(),
            'exp' => time() + 3600,
            // 这两个字段是给 safe.php 做对照用的：合法令牌带 iss/aud，对照页才认
            'iss' => 'jwt-lab',
            'aud' => 'jwt-lab-web',
        ]));

        $input = $header . '.' . $payload;
        $priv = openssl_pkey_get_private((string)file_get_contents(PRIV));

        // 私钥读不到时 openssl_sign 会失败并留下空签名 —— 那签出来的就是个坏令牌，
        // 后面排查会很迷惑。这里直接说清楚。
        if ($priv === false || !openssl_sign($input, $rawsig, $priv, OPENSSL_ALGO_SHA256)) {
            $msg = '签发失败：读不到私钥（权限问题，检查 keys/rsa_private.pem）';
        } else {
            $token = $input . '.' . b64u($rawsig);
            setcookie('token', $token, ['path' => '/', 'httponly' => false]);
        }
    } else {
        $msg = '用户名或密码错误';
    }
}

if ($token !== '') {
    $alg = jwt_header($token)['alg'] ?? 'RS256';
    [$h, $p, $s] = jwt_parts($token);
    $input = $h . '.' . $p;
    $pub = file_get_contents(PUB);

    if ($alg === 'HS256') {
        // ★ 漏洞点：把公钥文本当成 HMAC 密钥用。公钥是公开的，等于密钥泄露。
        $ok = hash_equals(sign_hs256($input, $pub), $s);
    } else {
        $ok = openssl_verify($input, b64u_decode($s), $pub, OPENSSL_ALGO_SHA256) === 1;
    }

    if ($ok) {
        $who = jwt_payload($token);
    } elseif ($msg === '') {
        $msg = '签名校验失败';
    }
}

page_head('L3 · 算法混淆', 'l3');
?>
<p class="sub">
    这次是「更安全」的 RS256：私钥签、公钥验，签名伪造不了。<br>
    公钥在这里：<a href="pub.pem">pub.pem</a>（本来就该公开，不然别人怎么验签？）
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
            管理员面板：<code><?= htmlspecialchars(read_flag(FLAG_L3)) ?></code>
        </div>
    <?php else: ?>
        <div class="hint">
            普通用户看不到 flag。<br>
            提示：服务端是按 <code>alg</code> 分支验签的。HS256 分支需要的是一段「密钥」——
            它从哪段字节里取的？
        </div>
    <?php endif; ?>
<?php endif; ?>

<?php page_foot(); ?>
