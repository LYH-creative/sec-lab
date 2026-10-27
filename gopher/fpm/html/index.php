<?php
// fpm 容器里一个「存在但没内容」的入口文件。
// L6 需要的只是 SCRIPT_FILENAME 指向一个真实存在的 .php，
// 真正执行的代码靠 PHP_VALUE auto_prepend_file=php://input 注入。
http_response_code(200);
echo "fpm ok\n";
