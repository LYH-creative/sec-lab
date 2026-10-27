<?php
require __DIR__ . '/common.php';

/**
 * L2：白名单 + 跟随重定向。
 *
 * 过滤只看字符串前缀，看起来挺严：只能访问内部网关。
 * 但网关自己提供 /r?to=<url> 的 302 跳转，而 curl 开 FOLLOWLOCATION 后
 * 不会校验跳转后的协议有没有变（新版本 libcurl 默认 REDIR_PROTOCOLS
 * 已限制为 http/https/ftp，PHP 的 curl 扩展在 8.x 里也跟着收紧了 ——
 * 所以这一关要故意把 REDIR_PROTOCOLS 放开，模拟老版本行为）。
 */

$url = isset($_GET['url']) ? trim($_GET['url']) : 'http://legacy-internal:8081/';
$err = null;
$res = null;

const GATEWAY = 'http://legacy-internal:8081/';

if (isset($_GET['url'])) {
    if (strpos($url, GATEWAY) !== 0) {
        $err = '只允许访问内部网关：必须以 ' . GATEWAY . ' 开头';
    } else {
        // follow=true：允许重定向，且允许跳到任意协议（模拟 php-curl 早期默认行为）
        $res = http_fetch($url, true, 8);
    }
}

$out = '';
if ($err) {
    $out .= '<div class="err">' . h($err) . '</div>';
}
if ($res) {
    $out .= render_response($res);
}

$body = '<h1>L2 · 302 换协议<span class="tag">whitelist</span></h1>'
      . '<p class="sub">过滤器只认前缀，可它没想到「跳转之后协议能变」。</p>'

      . '<h2>现状</h2>'
      . '<p>这台机器上有个 URL 抓取接口，白名单写死成只能访问内部网关：</p>'
      . '<pre class="cmd">' . h("strpos(\$url, 'http://legacy-internal:8081/') === 0") . '</pre>'
      . '<p>网关本身（8081）只有一个功能：</p>'
      . '<pre class="cmd">' . h("GET /r?to=<url>   → 302 Location: <url>") . '</pre>'
      . '<p>它对 <code>to</code> 的校验只检查协议名是不是 http/https/gopher —— '
      . '运维的想法是「反正只是拼个链接」。</p>'

      . '<h2>目标</h2>'
      . '<p>flag 在 <code>legacy-internal:70</code> 的 gopher 实例里，'
      . 'HTTP 那侧根本不提供文件。你只能让 gopher 协议去读它。</p>'

      . '<h2>试试</h2>'
      . url_form('l2.php', $url, GATEWAY) . $out

      . '<h2>卡住了看这</h2>'
      . '<ul class="hint">'
      . '<li>curl 收到 302 会重新发起请求，<b>新的 URL 协议可以完全不同</b>。</li>'
      . '<li>所以第一步是让请求命中网关的 <code>/r</code>，第二步才是 gopher。</li>'
      . '<li><code>to</code> 参数里的 <code>:</code> 和 <code>/</code> 会被 URL 解析吃掉，'
      . '记得把整个 <code>to</code> 的值做一次 URL 编码（<code>%3A%2F%2F</code>）。</li>'
      . '<li>gopher 里读文件用 type <code>0</code>：<code>gopher://legacy-internal:70/0/l2.txt</code>。</li>'
      . '</ul>';

page('l2', 'L2 · 302 换协议', $body);
