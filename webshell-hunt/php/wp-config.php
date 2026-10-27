<?php
/**
 * WordPress 基础配置文件。
 *
 * 本文件包含以下配置：数据库设置、密钥、语言设置。
 */

// ** 数据库设置 ** //
define( 'DB_NAME', 'wordpress' );
define( 'DB_USER', 'wp_user' );
define( 'DB_PASSWORD', 'Wp!2025#Shop' );
define( 'DB_HOST', 'localhost' );
define( 'DB_CHARSET', 'utf8mb4' );
define( 'DB_COLLATE', '' );

/**#@+
 * 认证密钥与会话唯一标识。
 */
define( 'AUTH_KEY',         'x9Kq2Lm8/vB3nR7pT1sW6yH4dF0gJ5aZ' );
define( 'SECURE_AUTH_KEY',  'c4Vh7Nb1mQ9xL2kT6rYw8pS3dF5gJ0aZ' );
define( 'LOGGED_IN_KEY',    'p3Rf9Kd2mN7xB1qT5vW8yL4hS6gJ0aZc' );
define( 'NONCE_KEY',        'w8Jd4Hm1nB6xK3qT9vR2yL5pS7gF0aZc' );
/**#@-*/

$table_prefix = 'wp_';

define( 'WP_DEBUG', false );

if ( ! defined( 'ABSPATH' ) ) {
	define( 'ABSPATH', __DIR__ . '/' );
}

require_once ABSPATH . 'wp-settings.php';
