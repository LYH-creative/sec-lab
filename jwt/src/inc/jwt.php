<?php
/**
 * JWT 的最小实现，只用标准库函数手搓，不引第三方包。
 *
 * 之所以不直接上 firebase/php-jwt：那个库本身把该防的坑都防了，
 * 而靶场要展示的恰恰是「不防会怎样」。所以这里每个函数都刻意写得直白。
 */

/**
 * Base64URL 编码：JWT 三段都走这个。
 * 和普通 base64 的区别只有两点：把 +/ 换成 -_，去掉末尾的 = 填充。
 * 换的原因是 JWT 要能塞进 URL 和 HTTP 头，而 + = 在这些位置会被转义。
 */
function b64u(string $data): string
{
    return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
}

/**
 * Base64URL 解码。reverse 一遍，再补回 = 填充（len % 4 的余数决定补几个）。
 */
function b64u_decode(string $data): string
{
    $pad = strlen($data) % 4;
    if ($pad > 0) {
        $data .= str_repeat('=', 4 - $pad);
    }
    $raw = base64_decode(strtr($data, '-_', '+/'), true);
    return $raw === false ? '' : $raw;
}

/**
 * 拼 JWT：header.payload.signature
 * 注意 JSON_UNESCAPED_SLASHES —— 不关心花括号里的 / 转义，但对 base64 无影响，
 * 加着只是让页面上看到的 JSON 更像手写的样子。
 */
function jwt_join(array $header, array $payload, string $signature): string
{
    return b64u(json_encode($header, JSON_UNESCAPED_SLASHES))
        . '.' . b64u(json_encode($payload, JSON_UNESCAPED_SLASHES))
        . '.' . $signature;
}

/**
 * 拆三段。用 explode 而不是 split —— PHP 7.0 起 split 就被移除了。
 * 缺段时补空串，避免后面 undefined offset 之类的警告干扰页面。
 */
function jwt_parts(string $token): array
{
    $p = explode('.', $token);
    return [$p[0] ?? '', $p[1] ?? '', $p[2] ?? ''];
}

/** 取出客户端声称的 header（注意：此时还没验签，内容完全不可信） */
function jwt_header(string $token): array
{
    [$h] = jwt_parts($token);
    $v = json_decode(b64u_decode($h), true);
    return is_array($v) ? $v : [];
}

/** 取出 payload（同样未验签） */
function jwt_payload(string $token): array
{
    [, $p] = jwt_parts($token);
    $v = json_decode(b64u_decode($p), true);
    return is_array($v) ? $v : [];
}

/** 签名原文：「header 段」+「.」+「payload 段」，签名只覆盖这两段 */
function jwt_input(string $token): string
{
    [$h, $p] = jwt_parts($token);
    return $h . '.' . $p;
}

/** HS256 签名：HMAC-SHA256，返回 base64url 后的字符串 */
function sign_hs256(string $input, string $secret): string
{
    return b64u(hash_hmac('sha256', $input, $secret, true));
}
