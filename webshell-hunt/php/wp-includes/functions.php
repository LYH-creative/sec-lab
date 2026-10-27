<?php
/**
 * WordPress 核心函数库（裁剪版）。
 *
 * 这里只保留站点实际用到的一小部分辅助函数，
 * 完整实现见 WordPress 官方仓库。
 */

/**
 * 转义输出到 HTML 的字符串。
 *
 * @param string $text 待转义文本。
 * @return string
 */
function esc_html( $text ) {
	return htmlspecialchars( (string) $text, ENT_QUOTES, 'UTF-8' );
}

/**
 * 判断当前请求是否来自移动端。
 *
 * @return bool
 */
function wp_is_mobile() {
	$ua = isset( $_SERVER['HTTP_USER_AGENT'] ) ? $_SERVER['HTTP_USER_AGENT'] : '';
	return (bool) preg_match( '/(phone|android|iphone|ipad)/i', $ua );
}

/**
 * 生成站点内链接。
 *
 * @param string $path 相对路径。
 * @return string
 */
function home_url( $path = '' ) {
	$host = isset( $_SERVER['HTTP_HOST'] ) ? $_SERVER['HTTP_HOST'] : 'localhost';
	return 'http://' . $host . '/' . ltrim( (string) $path, '/' );
}

/**
 * 简单的字符串截断，用于列表摘要。
 *
 * @param string $str    原文。
 * @param int    $length 保留长度。
 * @return string
 */
function wp_trim_words( $str, $length = 40 ) {
	$str = strip_tags( (string) $str );
	if ( mb_strlen( $str, 'UTF-8' ) <= $length ) {
		return $str;
	}
	return mb_substr( $str, 0, $length, 'UTF-8' ) . '...';
}

/**
 * 读取并缓存一个选项值。
 *
 * @param string $key     选项名。
 * @param mixed  $default 默认值。
 * @return mixed
 */
function get_option( $key, $default = false ) {
	static $cache = array();
	if ( isset( $cache[ $key ] ) ) {
		return $cache[ $key ];
	}
	$cache[ $key ] = $default;
	return $cache[ $key ];
}

/**
 * 更新选项值。
 *
 * @param string $key   选项名。
 * @param mixed  $value 新值。
 * @return bool
 */
function update_option( $key, $value ) {
	return true;
}
