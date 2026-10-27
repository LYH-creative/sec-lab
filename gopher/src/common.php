<?php
/**
 * 公共函数：页面骨架、curl 代理、URL 过滤。
 *
 * 这个靶场所有关卡共用一个思路：
 *   用户给一个 URL → 服务端用 curl 去取 → 把响应原样打回页面。
 * 区别只在于每关的过滤策略不同，以及后面的目标服务不同。
 */

function h($s)
{
    return htmlspecialchars((string)$s, ENT_QUOTES, 'UTF-8');
}

/** 关卡元数据：顺序就是 index 里的展示顺序 */
function levels()
{
    return [
        'l1' => ['name' => 'L1 · Gopher 协议本体', 'tag' => 'no-filter',
                 'desc' => '没有 SSRF，直接对 Gopher 服务发 selector，搞清协议长什么样'],
        'l2' => ['name' => 'L2 · 302 换协议', 'tag' => 'whitelist',
                 'desc' => '只允许访问内部 HTTP 网关，但网关自己会 302 到 gopher'],
        'l3' => ['name' => 'L3 · 打 Redis 读 flag', 'tag' => 'blacklist',
                 'desc' => '黑名单只挡了 file://，gopher:// 畅通无阻'],
        'l4' => ['name' => 'L4 · 打 Redis 写 WebShell', 'tag' => 'same-hole',
                 'desc' => '同一个注入点，把 RESP 命令换成 CONFIG SET + SAVE'],
        'l5' => ['name' => 'L5 · 打 MySQL 协议包', 'tag' => 'raw-tcp',
                 'desc' => '手工拼 HandshakeResponse41 + COM_QUERY，一个包完成登录和查询'],
        'l6' => ['name' => 'L6 · 打 PHP-FPM FastCGI', 'tag' => 'raw-tcp',
                 'desc' => '拼 FastCGI 记录，用 PHP_VALUE 改 auto_prepend_file'],
    ];
}

/** 页面骨架 */
function page($slug, $title, $body)
{
    $levels = levels();
    $nav = '';
    foreach ($levels as $k => $v) {
        $cls = ($k === $slug) ? 'nav-item active' : 'nav-item';
        $nav .= sprintf('<a class="%s" href="%s.php">%s</a>', $cls, $k, h($v['name']));
    }
    echo <<<HTML
<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{$title} · gopher lab</title>
<link rel="stylesheet" href="style.css">
</head>
<body>
<header class="top">
  <a class="brand" href="index.php">gopher<span>_lab</span></a>
  <nav class="nav">{$nav}</nav>
</header>
<main class="wrap">
{$body}
</main>
<footer class="foot">本地靶场 · 仅限授权环境使用</footer>
</body>
</html>
HTML;
}

/**
 * 用 curl 取一个 URL。
 *
 * follow=true 时开 CURLOPT_FOLLOWLOCATION —— 注意这是 L2 的关键：
 * libcurl 跟随 302 时不会校验协议是否变了（除非设了 CURLOPT_REDIR_PROTOCOLS），
 * 所以 http → gopher 的跳转它是照跟不误的。
 *
 * 响应体用 WRITEFUNCTION 自己攒，而不是靠 RETURNTRANSFER。
 * 原因：打 Redis / MySQL 这类服务时，对端不一定主动关连接，
 * curl_exec 会一直等到超时然后**丢弃**已经收到的数据（返回 false）。
 * 自己写回调就能把「超时前收到的部分」保住 —— 而这些部分往往就是 flag。
 *
 * @return array{code:int,headers:array,body:string,err:string,redirects:int}
 */
function http_fetch($url, $follow = false, $timeout = 8)
{
    $ch = curl_init($url);
    $headers = [];
    $body = '';
    $opts = [
        CURLOPT_WRITEFUNCTION  => function ($ch, $chunk) use (&$body) {
            $body .= $chunk;
            return strlen($chunk);
        },
        CURLOPT_TIMEOUT        => $timeout,
        CURLOPT_CONNECTTIMEOUT => 4,
        CURLOPT_HEADERFUNCTION => function ($ch, $line) use (&$headers) {
            $headers[] = rtrim($line);
            return strlen($line);
        },
    ];
    if ($follow) {
        $opts[CURLOPT_FOLLOWLOCATION] = true;
        $opts[CURLOPT_MAXREDIRS] = 5;
        $opts[CURLOPT_REDIR_PROTOCOLS] = CURLPROTO_ALL;  // 模拟 php-curl 早期默认行为
    }
    curl_setopt_array($ch, $opts);

    curl_exec($ch);
    $err  = curl_error($ch);
    $code = (int)curl_getinfo($ch, CURLINFO_HTTP_CODE);
    $redirs = (int)curl_getinfo($ch, CURLINFO_REDIRECT_COUNT);
    curl_close($ch);

    return [
        'code'      => $code,
        'headers'   => $headers,
        'body'      => $body,
        'err'       => $err,
        'redirects' => $redirs,
    ];
}

/** 把 curl 结果渲染成「响应面板」 */
function render_response($res)
{
    $meta = sprintf('HTTP %d · 重定向 %d 次', $res['code'], $res['redirects']);
    if ($res['err'] !== '') {
        $meta .= ' · ' . $res['err'];
    }
    $hdr = '';
    foreach ($res['headers'] as $line) {
        $hdr .= h($line) . "\n";
    }
    // gopher / redis / mysql 返回的是二进制，这里只保留可打印字符，
    // 但保留 \r\n 的视觉效果，方便看清协议帧
    $body = preg_replace('/[^\x09\x0a\x0d\x20-\x7e]/', '.', $res['body']);
    echo '<div class="resp"><div class="resp-meta">' . h($meta) . '</div>';
    if ($hdr !== '') {
        echo '<pre class="resp-head">' . $hdr . '</pre>';
    }
    echo '<pre class="resp-body">' . ($body === '' ? '(空响应)' : $body) . '</pre></div>';
}

/** 表单 */
function url_form($action, $value, $placeholder = '', $label = '目标 URL')
{
    echo '<form class="probe" method="get" action="' . h($action) . '">';
    echo '<label>' . h($label) . '</label>';
    echo '<div class="row"><input type="text" name="url" value="' . h($value) . '" '
        . 'placeholder="' . h($placeholder) . '" autocomplete="off">';
    echo '<button type="submit">发送</button></div></form>';
}

/**
 * 另一种 SSRF 实现：直接开 socket 把字节灌进去。
 *
 * 为什么不一律用 curl？
 *   L5 / L6 的目标是二进制协议（MySQL、FastCGI），报文里天然带 NUL 字节。
 *   而 libcurl 的 gopher 实现内部走 C 字符串（strlen），URL 里 %00 解出来就是
 *   截断点，实测整条 payload 会变成空。真实攻防里这是个硬限制：
 *   能不能打 MySQL，取决于 SSRF 是怎么实现的。
 *
 *   这个函数用 PHP 的 stream_socket_client，PHP 字符串本身二进制安全，
 *   所以 NUL 能原样发出去。代价是它不会像 curl 那样替我们补 CRLF ——
 *   字节流完全由 payload 决定。
 *
 * @return array{code:int,headers:array,body:string,err:string,redirects:int}
 */
function gopher_socket($url, $timeout = 6)
{
    // 不用 parse_url：它在 C 层用 char*，遇到 %00 解码后的 NUL 会截断。
    // 正则匹配是二进制安全的。
    if (!preg_match('#^gopher://([A-Za-z0-9._-]+):(\d{1,5})/_(.*)$#s', $url, $m)) {
        return ['code' => 0, 'headers' => [], 'body' => '', 'redirects' => 0,
                'err' => 'URL 必须写成 gopher://host:port/_<payload>'];
    }
    $host = $m[1];
    $port = (int)$m[2];
    // 这里再解一次码：$_GET 已经把 query string 解过一层，
    // payload 自身的 %XX 还剩一层，解完才是真正要发的字节。
    $data = rawurldecode($m[3]);

    $fp = @stream_socket_client("tcp://$host:$port", $eno, $estr, 3);
    if (!$fp) {
        return ['code' => 0, 'headers' => [], 'body' => '', 'redirects' => 0,
                'err' => sprintf('连接 %s:%d 失败 (%d %s)', $host, $port, $eno, $estr)];
    }
    stream_set_timeout($fp, $timeout);
    fwrite($fp, $data);

    $out = '';
    while (!feof($fp)) {
        $chunk = fread($fp, 8192);
        if ($chunk === false) {
            break;
        }
        if ($chunk === '') {
            $meta = stream_get_meta_data($fp);
            if ($meta['timed_out']) {
                break;
            }
            continue;
        }
        $out .= $chunk;
        if (strlen($out) > 262144) {
            break;
        }
    }
    fclose($fp);

    return ['code' => 0, 'headers' => [], 'body' => $out, 'redirects' => 0, 'err' => ''];
}
