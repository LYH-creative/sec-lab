<?php
require __DIR__ . '/common.php';

/**
 * L1：Gopher 协议本体。
 *
 * 这关没有 SSRF、没有过滤 —— 就是一个裸的 gopher 客户端。
 * 目的是让你看见：整个协议只有「一行 selector + CRLF」这么点东西。
 *
 * 真实打点用的是 curl：
 *     curl -v 'gopher://127.0.0.1:7070/1/'
 * 其中 URL 里的 /1/ 表示「type=1 目录」，后面的 selector 才是发给服务端的字符串。
 */

$host = isset($_GET['host']) ? trim($_GET['host']) : 'legacy-public';
$port = isset($_GET['port']) ? (int)$_GET['port'] : 70;
$sel  = isset($_GET['sel']) ? $_GET['sel'] : '/';
$raw  = null;
$err  = null;

if (isset($_GET['host'])) {
    if (!preg_match('/^[a-zA-Z0-9._-]+$/', $host)) {
        $err = 'host 只能是主机名';
    } elseif ($port < 1 || $port > 65535) {
        $err = '端口不合法';
    } else {
        $fp = @fsockopen($host, $port, $eno, $estr, 3);
        if (!$fp) {
            $err = sprintf('连接 %s:%d 失败 (%d %s)', $host, $port, $eno, $estr);
        } else {
            stream_set_timeout($fp, 3);
            fwrite($fp, $sel . "\r\n");
            $raw = '';
            while (!feof($fp)) {
                $chunk = fread($fp, 4096);
                if ($chunk === false || $chunk === '') {
                    break;
                }
                $raw .= $chunk;
                if (strlen($raw) > 65536) {
                    break;
                }
            }
            fclose($fp);
        }
    }
}

function hexdump($s, $limit = 160)
{
    $s = substr($s, 0, $limit);
    $out = '';
    foreach (str_split($s, 16) as $i => $line) {
        $hex = '';
        $asc = '';
        foreach (str_split($line) as $ch) {
            $o = ord($ch);
            $hex .= sprintf('%02x ', $o);
            $asc .= ($o >= 0x20 && $o <= 0x7e) ? $ch : '.';
        }
        $out .= sprintf("%04x  %-48s %s\n", $i * 16, $hex, $asc);
    }
    return $out;
}

$form = '<form class="probe" method="get" action="l1.php">'
      . '<label>gopher 客户端（直接裸 TCP，没有过滤）</label>'
      . '<div class="row" style="flex-wrap:wrap">'
      . '<input type="text" name="host" value="' . h($host) . '" style="max-width:210px" placeholder="host">'
      . '<input type="text" name="port" value="' . h($port) . '" style="max-width:90px" placeholder="port">'
      . '<input type="text" name="sel"  value="' . h($sel) . '"  placeholder="/">'
      . '<button type="submit">发送</button></div></form>';

$out = '';
if ($err) {
    $out .= '<div class="err">' . h($err) . '</div>';
}
if ($raw !== null) {
    $pretty = preg_replace('/[^\x09\x0a\x0d\x20-\x7e]/', '.', $raw);
    $out .= '<div class="resp"><div class="resp-meta">'
          . strlen($raw) . ' 字节</div>'
          . '<pre class="resp-body">' . h($pretty) . '</pre>'
          . '<pre class="resp-head">' . h(hexdump($raw)) . '</pre></div>';
}

$body = '<h1>L1 · Gopher 协议本体<span class="tag">no-filter</span></h1>'
      . '<p class="sub">先把协议本身摸清楚，再谈 SSRF。这一关不涉及任何漏洞。</p>'

      . '<h2>协议长什么样</h2>'
      . '<p>RFC 1436 定义的 gopher 客户端请求，就是<b>一行 selector + CRLF</b>，没有头、没有 body：</p>'
      . '<pre class="cmd">' . h('/\r\n') . '            ← 请求根菜单'
      . "\n" . h('/l1.txt\r\n') . '       ← 请求某个文件' . '</pre>'
      . '<p>服务端回一串菜单行，每行五个字段用 TAB 分隔，最外层以单独一行 <code>.</code> 结束：</p>'
      . '<pre class="cmd">' . h('<type><display>\t<selector>\t<host>\t<port>\r\n') . '</pre>'
      . '<p>type 里 <code>0</code> 是文本文件，<code>1</code> 是目录，'
      . '<code>i</code> 是信息行（不可点）。</p>'

      . '<h2>抓 flag</h2>'
      . '<p>目标服务是内网里的 <code>legacy-public:70</code>，flag 就在它的资料目录里。</p>'
      . $form . $out

      . '<h2>等价的一条 curl</h2>'
      . '<pre class="cmd">' . h("curl -v 'gopher://127.0.0.1:7070/1/'\ncurl -v 'gopher://127.0.0.1:7070/0/l1.txt'") . '</pre>'
      . '<ul class="hint">'
      . '<li>URL 里 <code>/1/</code> 的第一个 <code>1</code> 是 gopher type，'
      . 'libcurl 会把它吃掉，只把后面的 selector 发出去。</li>'
      . '<li>所以 <code>gopher://h:70/0/l1.txt</code> 实际发的是 <code>/l1.txt\\r\\n</code>。</li>'
      . '<li>这个「URL 里塞任意字节」的能力，就是后面几关全部利用的基础 —— '
      . '<code>%0d%0a</code> 解出来就是 CRLF，能伪造任意协议的多行报文。</li>'
      . '</ul>';

page('l1', 'L1 · Gopher 协议本体', $body);
