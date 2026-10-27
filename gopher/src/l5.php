<?php
require __DIR__ . '/common.php';

/**
 * L5：gopher 直接讲 MySQL 协议。
 *
 * 这一关没有 HTTP 中转，没有中间件 —— gopher 把字节原样灌进 3306，
 * 所以你得自己充当 MySQL 客户端：先发认证包，再发 COM_QUERY。
 *
 * 前提是目标账号密码为空。空密码的 HandshakeResponse41 里
 * auth_response 长度为 0，不依赖服务端随机 salt，
 * 因此可以离线把整个字节流一次性拼好 —— 这是 gopher 打 MySQL 能成立的关键。
 */

$url = isset($_GET['url']) ? trim($_GET['url']) : '';
$err = null;
$res = null;

$deny = ['file://', 'dict://', 'ftp://', 'php://', 'data://', 'zlib://'];

if (isset($_GET['url'])) {
    if ($url === '') {
        $err = '给个 URL';
    } else {
        foreach ($deny as $d) {
            if (stripos($url, $d) !== false) {
                $err = '禁止的协议：' . $d;
                break;
            }
        }
    }
    if ($err === null) {
        // 这一关用 socket 直发，不用 curl —— 原因见页面里的「实现差异」
        $res = gopher_socket($url, 6);
    }
}

$out = '';
if ($err) {
    $out .= '<div class="err">' . h($err) . '</div>';
}
if ($res) {
    $out .= render_response($res);
}

$body = '<h1>L5 · 打 MySQL 协议包<span class="tag">raw-tcp</span></h1>'
      . '<p class="sub">这回对手是个二进制协议，全靠手工拼字节。</p>'

      . '<h2>目标</h2>'
      . '<p><code>db:3306</code>，MariaDB。运维图省事建了个免密账号：</p>'
      . '<pre class="cmd">' . h("user: ssrf\npassword: (空)\ndb: secret  →  表 flag(val varchar)") . '</pre>'

      . url_form('l5.php', $url, 'gopher://db:3306/_...') . $out

      . '<h2>MySQL 报文结构</h2>'
      . '<p>每个包都是 <b>3 字节小端长度 + 1 字节序号 + 载荷</b>，序号从 0 开始递增：</p>'
      . '<pre class="cmd">' . h("[ len:3 LE ][ seq:1 ][ payload ]") . '</pre>'
      . '<p>要发两个包，一次连接内完成：</p>'
      . '<ul class="hint">'
      . '<li><b>seq=1</b> HandshakeResponse41：<br>'
      . '<code>capabilities(4) max_packet(4) charset(1) 填充(23) username\\0 auth_len(1) [auth_data]</code><br>'
      . '空密码时 <code>auth_len = 0</code>，后面不跟任何字节。</li>'
      . '<li><b>seq=0</b> COM_QUERY：<code>0x03</code> + SQL 文本。</li>'
      . '</ul>'
      . '<p>capabilities 至少要带上 <code>CLIENT_PROTOCOL_41 (0x0200)</code> 和 '
      . '<code>CLIENT_SECURE_CONNECTION (0x8000)</code>，否则服务端会按老协议回你。</p>'
      . '<p>查询语句：<code>SELECT val FROM secret.flag</code>。'
      . '返回的 ResultSet 是二进制，flag 会以明文字节出现在响应里。</p>'

      . '<h2>为什么空密码才可行</h2>'
      . '<p>有密码时要算 <code>SHA1(pass) XOR SHA1(salt + SHA1(SHA1(pass)))</code>，'
      . '而 <code>salt</code> 是每次连接随机给的 —— gopher 只发不收，拿不到 salt，就拼不出来。'
      . '这是这条路唯一的硬限制。</p>'

      . '<h2>一个必须知道的实现差异</h2>'
      . '<p>L3/L4 用的是 <code>curl</code>，这一关不是。因为 libcurl 的 gopher 实现内部走 C 字符串，'
      . 'URL 里的 <code>%00</code> 会被当作结束符 —— 而 MySQL 包头里 <code>长度(3字节小端)</code> '
      . '几乎必然带 NUL，整条 payload 会直接变空。</p>'
      . '<p>所以这个接口改成了 <code>stream_socket_client</code> 直发，PHP 字符串二进制安全，'
      . 'NUL 能原样发出去。副作用是它<b>不会替你补 CRLF</b>，字节流完全由 payload 决定。</p>'
      . '<p>真实攻防里能不能打 MySQL，往往就取决于 SSRF 是 curl 实现的还是 socket 实现的 —— 这是个很实际的判断点。</p>'

      . '<p>参考脚本：<code>poc/05_mysql_gopher.py</code>。'
      . '它会从宿主机直接验证「3306 到底通不通」—— 答案是不通，因为没映射端口。</p>';

page('l5', 'L5 · 打 MySQL 协议包', $body);
