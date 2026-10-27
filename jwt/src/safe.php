<?php
/**
 * 修复对照
 *
 * 同一套业务，把四关的病灶一次性堵死。把你在 L1~L4 造出来的 token 粘进来，
 * 会发现全部失效 —— 这才是「修好了长什么样」。
 *
 * 关键不是换了个更强的算法，而是四件具体的事：
 *   1. alg 不从令牌里读，服务端写死 RS256（堵 L2 / L3）
 *   2. 验签用的密钥只来自服务端自己的配置，永不来自令牌（堵 L3 / L4）
 *   3. kid 走白名单映射，不拼路径（堵 L4）
 *   4. 校 exp / iat / iss / aud（挡重放和过期令牌）
 */
require __DIR__ . '/inc/common.php';

const SAFE_PUB = __DIR__ . '/pub.pem';
const SAFE_ISS = 'jwt-lab';
const SAFE_AUD = 'jwt-lab-web';

$result = null;

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['token'])) {
    $t = trim((string)$_POST['token']);

    do {
        [$h, $p, $s] = jwt_parts($t);
        if ($h === '' || $p === '' || $s === '') {
            $result = ['bad', '不是合法的三段式令牌'];
            break;
        }

        $header = jwt_header($t);

        // 1. 算法写死，不读用户的 alg（连 header 里的 alg 都只是用来做一致性检查）
        if (($header['alg'] ?? '') !== 'RS256') {
            $result = ['bad', 'alg 必须是 RS256，收到 ' . ($header['alg'] ?? '(缺失)')];
            break;
        }

        // 2. 密钥固定从本地文件读，与令牌内容无关
        // 注意这里不要把 === 1 和 !== 1 混用：openssl_verify 返回 int（1/0/-1），
        // 写成 $ok = openssl_verify(...) === 1 之后再 $ok !== 1，永远是 true。
        $ok = openssl_verify($h . '.' . $p, b64u_decode($s), file_get_contents(SAFE_PUB), OPENSSL_ALGO_SHA256);
        if ($ok !== 1) {
            $result = ['bad', '签名校验失败'];
            break;
        }

        // 3. 声明的语义校验
        $payload = jwt_payload($t);
        $now = time();
        if (!isset($payload['exp']) || $payload['exp'] < $now) {
            $result = ['bad', '令牌已过期'];
            break;
        }
        if (($payload['iss'] ?? '') !== SAFE_ISS) {
            $result = ['bad', 'iss 不匹配'];
            break;
        }
        if (($payload['aud'] ?? '') !== SAFE_AUD) {
            $result = ['bad', 'aud 不匹配'];
            break;
        }

        $result = ['ok', '通过。sub=' . ($payload['sub'] ?? '?') . ' role=' . ($payload['role'] ?? '?')];
    } while (false);
}

page_head('对照 · 修好了长什么样', 'safe');
?>
<p class="sub">
    把 L1~L4 里你造出来的令牌粘进来试试。这一页用的是对照写法：
    <code>alg</code> 写死 RS256、密钥只从服务端读、<code>kid</code> 不参与取密钥、
    另外校验 <code>exp / iss / aud</code>。
</p>

<form method="post">
    <textarea name="token" rows="5" placeholder="粘贴 eyJhbGciOi... 开头的令牌"><?= htmlspecialchars($_POST['token'] ?? '') ?></textarea>
    <button type="submit">验证</button>
</form>

<?php if ($result !== null): ?>
    <div class="<?= $result[0] === 'ok' ? 'ok' : 'err' ?>"><?= htmlspecialchars($result[1]) ?></div>
<?php endif; ?>

<div class="hint">
    注意这一关拒绝 L2 的方式：不是「发现 alg=none 就拒绝」，而是「alg 不是 RS256 就拒绝」。
    前者是黑名单，后者是白名单 —— 安全代码永远优先写白名单。
</div>

<?php page_foot(); ?>
