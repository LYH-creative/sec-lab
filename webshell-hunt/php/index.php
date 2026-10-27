<?php
/**
 * WordPress 前端入口文件。
 *
 * 本文件不执行任何逻辑，只负责加载 wp-blog-header.php，
 * 后者会完成环境初始化并渲染主题。
 *
 * @package WordPress
 */

/**
 * 告诉 WordPress 加载主题并输出页面。
 *
 * @var bool
 */
define( 'WP_USE_THEMES', true );

/** 加载 WordPress 环境与模板 */
require __DIR__ . '/wp-blog-header.php';
