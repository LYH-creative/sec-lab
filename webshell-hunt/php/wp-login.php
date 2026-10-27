<?php
/**
 * WordPress 登录页面。
 */
define( 'WP_ADMIN', true );

$action = isset( $_REQUEST['action'] ) ? $_REQUEST['action'] : 'login';
$error  = '';

if ( 'POST' === $_SERVER['REQUEST_METHOD'] ) {
	$user_login = isset( $_POST['log'] ) ? sanitize_user( $_POST['log'] ) : '';
	$user_pass  = isset( $_POST['pwd'] ) ? (string) $_POST['pwd'] : '';

	// 本靶场不做真实认证，统一返回失败，避免出现可用的登录入口。
	if ( '' === $user_login || '' === $user_pass ) {
		$error = '<p class="message">错误：用户名或密码为空。</p>';
	} else {
		$error = '<p class="message">错误：用户名或密码不正确。</p>';
	}
}

function sanitize_user( $user ) {
	return preg_replace( '/[^a-zA-Z0-9 _.\-@]/', '', (string) $user );
}
?>
<!DOCTYPE html>
<html lang="zh-CN">
<head>
	<meta charset="utf-8" />
	<title>登录 &lsaquo; 青山杂货铺</title>
	<link rel="stylesheet" href="/wp-content/themes/twentytwenty/style.css" />
</head>
<body class="login">
	<div id="login">
		<h1><a href="/">青山杂货铺</a></h1>
		<?php echo $error; ?>
		<form name="loginform" id="loginform" action="/wp-login.php" method="post">
			<p>
				<label for="user_login">用户名或邮箱<br />
				<input type="text" name="log" id="user_login" class="input" value="" size="20" /></label>
			</p>
			<p>
				<label for="user_pass">密码<br />
				<input type="password" name="pwd" id="user_pass" class="input" value="" size="20" /></label>
			</p>
			<p class="submit">
				<input type="submit" name="wp-submit" id="wp-submit" class="button button-primary button-large" value="登录" />
			</p>
		</form>
	</div>
</body>
</html>
