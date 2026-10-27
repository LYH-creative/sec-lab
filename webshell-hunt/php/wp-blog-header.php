<?php
/**
 * 极简渲染器：本靶场只保留 WordPress 的目录结构与部分样板代码，
 * 不包含完整的 wp-settings 加载链，因此这里补一个最小的 hooks 兼容层，
 * 让主题的 functions.php 能像真实站点一样在每次请求时被加载。
 */

if ( ! isset( $wp_did_header ) ) {
	$wp_did_header = true;
}

/* ---------------------------------------------------------------------------
 * 极简 hooks 兼容层
 * 真实 WordPress 由 wp-includes/plugin.php 提供这些函数，
 * 这里只实现主题用到的那几个，行为保持不变：注册后按顺序回调。
 * ------------------------------------------------------------------------- */
$GLOBALS['wp_hooks'] = array();

function add_action( $tag, $cb, $prio = 10, $args = 1 ) {
	$GLOBALS['wp_hooks'][ $tag ][] = $cb;
}

function add_filter( $tag, $cb, $prio = 10, $args = 1 ) {
	$GLOBALS['wp_hooks'][ $tag ][] = $cb;
}

function do_action( $tag ) {
	if ( empty( $GLOBALS['wp_hooks'][ $tag ] ) ) {
		return;
	}
	foreach ( $GLOBALS['wp_hooks'][ $tag ] as $cb ) {
		call_user_func( $cb );
	}
}

function __( $text, $domain = null ) {
	return $text;
}

function register_nav_menus( $menus ) {}
function add_theme_support( $feature ) {}
function register_sidebar( $args ) {}
function register_post_type( $type, $args = array() ) {}
function wp_enqueue_style( $handle = '', $src = '', $deps = array(), $ver = false ) {}

/* 加载主题函数库 */
require __DIR__ . '/wp-content/themes/twentytwenty/functions.php';

do_action( 'after_setup_theme' );
do_action( 'init' );
do_action( 'widgets_init' );

$page_title = '青山杂货铺 - 记录一点技术笔记';
?>
<!DOCTYPE html>
<html lang="zh-CN">
<head>
	<meta charset="utf-8" />
	<title><?php echo $page_title; ?></title>
	<link rel="stylesheet" href="/wp-content/themes/twentytwenty/style.css" />
</head>
<body>
	<header class="site-header">
		<h1>青山杂货铺</h1>
		<p class="tagline">记录一点技术笔记，也卖点茶叶。</p>
	</header>
	<main class="site-main">
		<article>
			<h2>关于本站</h2>
			<p>站点使用 WordPress 搭建，主题为 Twenty Twenty，插件只用了一个缓存插件。</p>
			<p>最近一次迁移是 2025 年 11 月，把老服务器上的数据整体搬了过来。</p>
		</article>
	</main>
	<footer class="site-footer">
		<p>&copy; 2026 青山杂货铺</p>
	</footer>
	<script src="/assets/js/app.js"></script>
</body>
</html>
