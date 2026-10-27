<?php
/**
 * 查询类（裁剪版）。
 *
 * @package WordPress
 */

class WP_Query {

	/**
	 * 查询参数。
	 *
	 * @var array
	 */
	public $query = array();

	/**
	 * 结果集。
	 *
	 * @var array
	 */
	public $posts = array();

	/**
	 * 构造函数。
	 *
	 * @param array $args 查询参数。
	 */
	public function __construct( $args = array() ) {
		$this->query = wp_parse_args( $args, array(
			'post_type'      => 'post',
			'posts_per_page' => 10,
			'paged'          => 1,
		) );
		$this->posts = array();
	}

	/**
	 * 执行查询。
	 *
	 * @return array
	 */
	public function get_posts() {
		return $this->posts;
	}

	/**
	 * 是否还有其他页。
	 *
	 * @return bool
	 */
	public function have_posts() {
		return false;
	}
}

/**
 * 合并默认参数。
 *
 * @param array $args     用户参数。
 * @param array $defaults 默认参数。
 * @return array
 */
function wp_parse_args( $args, $defaults = array() ) {
	if ( is_object( $args ) ) {
		$args = get_object_vars( $args );
	}
	if ( ! is_array( $args ) ) {
		$args = array();
	}
	return array_merge( $defaults, $args );
}
