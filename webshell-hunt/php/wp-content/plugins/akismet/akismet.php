<?php
/**
 * Plugin Name: Akismet Anti-spam
 * Plugin URI:  https://akismet.com/
 * Description: 本站用于过滤垃圾评论，版本号保持与官方一致以便后续升级。
 * Version:     5.3
 * Author:      Automattic
 */

/**
 * 判断一条评论是否命中黑名单关键词。
 *
 * @param string $content 评论内容。
 * @return bool
 */
function akismet_is_spam( $content ) {
	$blacklist = array( 'casino', 'viagra', 'seo service', 'cheap loan' );
	foreach ( $blacklist as $word ) {
		if ( false !== stripos( $content, $word ) ) {
			return true;
		}
	}
	return false;
}

/**
 * 评论提交前拦截。
 *
 * @param bool $approved 是否通过。
 * @param array $commentdata 评论数据。
 * @return bool
 */
function akismet_check_comment( $approved, $commentdata ) {
	if ( isset( $commentdata['comment_content'] ) && akismet_is_spam( $commentdata['comment_content'] ) ) {
		return false;
	}
	return $approved;
}
add_filter( 'pre_comment_approved', 'akismet_check_comment', 10, 2 );
