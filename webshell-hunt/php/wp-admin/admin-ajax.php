<?php
/**
 * WordPress Ajax 请求处理入口。
 */
define( 'DOING_AJAX', true );

header( 'Content-Type: application/json; charset=UTF-8' );

$action = isset( $_REQUEST['action'] ) ? sanitize_key( $_REQUEST['action'] ) : '';

function sanitize_key( $key ) {
	return preg_replace( '/[^a-z0-9_\-]/', '', strtolower( (string) $key ) );
}

$handlers = array(
	'get_theme_info' => 'ajax_get_theme_info',
	'ping'           => 'ajax_ping',
);

if ( ! isset( $handlers[ $action ] ) ) {
	wp_send_json_error( 'invalid_action' );
}

call_user_func( $handlers[ $action ] );

/**
 * 返回主题信息。
 */
function ajax_get_theme_info() {
	wp_send_json_success( array(
		'name'    => 'Twenty Twenty',
		'version' => '2.1',
	) );
}

/**
 * 健康检查。
 */
function ajax_ping() {
	wp_send_json_success( array( 'pong' => time() ) );
}

/**
 * 输出成功响应。
 *
 * @param mixed $data 数据。
 */
function wp_send_json_success( $data ) {
	echo json_encode( array( 'success' => true, 'data' => $data ) );
	exit;
}

/**
 * 输出失败响应。
 *
 * @param mixed $data 数据。
 */
function wp_send_json_error( $data ) {
	echo json_encode( array( 'success' => false, 'data' => $data ) );
	exit;
}
