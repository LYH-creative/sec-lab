<?php
/**
 * 控制面板首页（裁剪版）。
 */
$modules = array(
	array( 'title' => '站点健康', 'desc' => 'PHP 版本 8.1，一切正常。' ),
	array( 'title' => '文章', 'desc' => '共 42 篇，草稿 3 篇。' ),
	array( 'title' => '评论', 'desc' => '待审核 0 条。' ),
);
?>
<!DOCTYPE html>
<html lang="zh-CN">
<head>
	<meta charset="utf-8" />
	<title>控制面板 &lsaquo; 青山杂货铺</title>
</head>
<body>
	<h1>控制面板</h1>
	<ul>
	<?php foreach ( $modules as $m ) : ?>
		<li>
			<strong><?php echo htmlspecialchars( $m['title'] ); ?></strong>
			<p><?php echo htmlspecialchars( $m['desc'] ); ?></p>
		</li>
	<?php endforeach; ?>
	</ul>
</body>
</html>
