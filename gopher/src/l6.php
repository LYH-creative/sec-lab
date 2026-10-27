<?php
require __DIR__ . '/common.php';

/**
 * L6：FastCGI 未授权。
 *
 * php-fpm 监听 9000 端口，只用 TCP，没有 TLS、没有认证 —— 任何能连上
 * 9000 的人都能以 fpm 的 worker 身份执行 PHP。正常情况下它只在 127.0.0.1
 * 或内网，是 nginx 的「后端」。一旦 SSRF 能打到 9000，nginx 这层就白做了。
 *
 * 本关为了聚焦「拼 FastCGI 包」，fpm 容器里 allow_url_include=On
 * （真实环境默认 Off，得配合任意文件写入才能打通）。
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
        // FastCGI 记录头里有 contentLength 的两字节大端，小包必然带 NUL，
        // 所以和 L5 一样走 socket 直发，不用 curl
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

$body = '<h1>L6 · 打 PHP-FPM / FastCGI<span class="tag">raw-tcp</span></h1>'
      . '<p class="sub">nginx 挡在前面的时候这一切都没问题；SSRF 一来，请求直接从后门进去了。</p>'

      . '<h2>目标</h2>'
      . '<p><code>fpm:9000</code>，纯 php-fpm，没有 nginx。'
      . '<code>/var/www/html/index.php</code> 存在（必要条件：SCRIPT_FILENAME 得指向真实文件）。'
      . 'flag 在 fpm 容器的 <code>/flag_l6</code>。</p>'

      . url_form('l6.php', $url, 'gopher://fpm:9000/_...') . $out

      . '<h2>FastCGI 记录格式</h2>'
      . '<p>8 字节固定头：</p>'
      . '<pre class="cmd">'
      . h("[version=1][type][requestId:2][contentLength:2][padding:1][reserved:1]")
      . '</pre>'
      . '<p>一个最小请求由三条记录组成：</p>'
      . '<ul class="hint">'
      . '<li><code>type=1</code> BEGIN_REQUEST，body 6 字节：<code>role=1(RESPONDER)</code> + <code>flags=0</code> + 5 字节填充</li>'
      . '<li><code>type=4</code> PARAMS，body 是一串 name-value 对</li>'
      . '<li><code>type=5</code> STDIN，body 就是请求体（PHP 代码）</li>'
      . '</ul>'
      . '<p>PARAMS 和 STDIN 结束时都要各补一条<b>空内容</b>的同类型记录，否则 fpm 会一直等。</p>'

      . '<h2>最容易拼错的地方</h2>'
      . '<p>FastCGI 的 name-value 对编码<b>不是</b>「名字长度 + 名字 + 值长度 + 值」，'
      . '而是把两个长度字段连在一起，字符串才依次跟上：</p>'
      . '<pre class="cmd">'
      . h("nameLen(1字节) + valueLen(1字节) + name + value")
      . '</pre>'
      . '<p>长度都小于 128 时各占 1 字节就够了。写成「交错」格式的话，fpm 会把 value 长度当成 '
      . 'name 的第一个字节去解析，然后直接把连接 RST 掉 —— 页面上表现为「空响应」，'
      . '日志里什么都没有，很难查。</p>'

      . '<h2>拿 flag 的两个参数</h2>'
      . '<pre class="cmd">'
      . h("PHP_VALUE   => auto_prepend_file=php://input\nallow_url_include = On  (容器里已开)")
      . '</pre>'
      . '<p><code>auto_prepend_file</code> 是 <code>PHP_INI_PERDIR</code>，'
      . '可以通过 <code>PHP_VALUE</code> 在请求级别覆盖 —— 于是 fpm 在执行 index.php 之前，'
      . '会先把 <code>php://input</code>（也就是你 STDIN 里那段 PHP 代码）include 进来。</p>'
      . '<p>STDIN 里放：<code>&lt;?php system(\'cat /flag_l6\'); ?&gt;</code></p>'

      . '<h2>必要的 PARAMS</h2>'
      . '<pre class="cmd">'
      . h("GATEWAY_INTERFACE  CGI/1.1\nSCRIPT_FILENAME    /var/www/html/index.php\nSCRIPT_NAME        /index.php\nREQUEST_METHOD     POST\nREQUEST_URI        /index.php\nDOCUMENT_ROOT      /var/www/html\nSERVER_PROTOCOL    HTTP/1.1\nCONTENT_LENGTH     <php 代码的字节数>\nCONTENT_TYPE       application/text")
      . '</pre>'
      . '<ul class="hint">'
      . '<li><code>SCRIPT_FILENAME</code> 不写会直接 <code>Primary script unknown</code>。</li>'
      . '<li>顺序无所谓，但 PARAMS 必须整块发完再发结束记录。</li>'
      . '<li>参考脚本：<code>poc/06_fastcgi_gopher.py</code>，它会把整包 dump 成十六进制，方便你对着调。</li>'
      . '</ul>';

page('l6', 'L6 · 打 PHP-FPM / FastCGI', $body);
