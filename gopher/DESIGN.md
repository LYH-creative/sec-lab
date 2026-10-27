# Gopher 靶场设计文档

> 这份文档讲两件事：Gopher 协议本身是什么，以及这六个关卡为什么这样设计。
> 操作步骤在 `README.md`，攻击载荷在 `poc/`，这里只谈原理和设计取舍。

---

## 一、Gopher 是什么

### 1.1 一段被 HTTP 干掉的历史

Gopher 诞生于 1991 年，明尼苏达大学（University of Minnesota）的一群程序员做的分布式文档检索系统。
名字来自校队吉祥物 Gopher（地鼠），也恰好和 "go-fer"（跑腿的人）谐音。

1993 年 3 月发布 RFC 1436。同年 2 月，明尼苏达大学宣布**将对 Gopher 服务端的商业使用收费**。
这个决定直接改变了互联网的走向：浏览器厂商开始把资源投向完全免费的 HTTP，
NCSA Mosaic 的重心转向 Web，Gopher 的流量在两年内断崖式下跌。

今天还活着的 Gopher 站点（比如 `gopher.floodgap.com`）基本是情怀项目。
但**协议本身没有消失** —— 它变成了 SSRF 里最锋利的那把刀，原因见第二节。

### 1.2 协议本体：一行字符串

Gopher 客户端和服务器之间的交互，简单到有点荒谬：

```
客户端 → 服务器：  <selector>\r\n
服务器 → 客户端：  <内容>\r\n.\r\n
```

selector 就是一行文本。`/` 表示根菜单，`/foo.txt` 表示读某个文件。
没有请求头，没有方法，没有状态码，没有 Cookie，没有任何认证。

对比一下 HTTP：

```
GET /foo.txt HTTP/1.1
Host: example.com
User-Agent: ...
Accept: ...
```

Gopher 只有第一行，而且连 `GET` 都没有 —— 因为它只有"读"这一个动作。

### 1.3 菜单（gophermap）

服务器返回目录时，回的是一个菜单。每行五个字段，用 TAB 分隔：

```
<type><display string>\t<selector>\t<host>\t<port>\r\n
```

一个真实例子（本靶场 L1 的返回）：

```
iGopher 老服务 / 只读资料库	fake	(NULL)	0
0about.txt	/about.txt	legacy-public	70
0l1.txt	/l1.txt	legacy-public	70
0notes.txt	/notes.txt	legacy-public	70
i-- EOF --	fake	(NULL)	0
.
```

最后单独一行 `.` 表示菜单结束 —— 和 SMTP、finger、NNTP 一样的老派做法。

type 字段决定客户端怎么处理这一行：

- `0` 文本文件 —— 读到后直接显示
- `1` 目录 —— 可以继续点进去
- `7` 搜索服务器 —— 会弹输入框，把关键词作为 selector 发过去
- `8` telnet 会话
- `9` 二进制文件
- `g` GIF、`I` 图片、`h` HTML、`s` 声音
- `i` 信息行 —— 只显示文字，不可点击
- `3` 错误

注意 `i` 这个类型：它让 Gopher 菜单可以写"标题"和"分隔线"，
这也是为什么上面的菜单第一行和最后一行都以 `i` 开头。

### 1.4 URL 形式

```
gopher://<host>:<port>/<type><selector>
```

`/` 后面的第一个字符是 type，剩下的才是真正的 selector。比如：

```
gopher://127.0.0.1:7070/1/
```

`1` 是 type（目录），selector 是 `/`。
libcurl 会把这个 `1` 吃掉，只发送 `/\r\n` 给服务器。

如果 type 位置的字符不是合法 type，libcurl 的行为是把它当成 selector 的一部分 ——
这也是为什么 SSRF 载荷习惯写成 `/_<payload>`：`_` 不是合法 type，
但正好占住 type 位，避免劫持 payload 的第一个字节。

> 实测记录：写 `gopher://host:port/%2A2%0D%0A...`（没有 `_`）时，
> 服务端收到的是 `2A2\r\n...` —— 开头的 `%` 被当成 type 吃掉了，
> 后面的 `2A2` 反而漏了出来。这个细节在手工拼载荷时很容易翻车。

---

## 二、为什么 SSRF 里 Gopher 是核弹

### 2.1 其他协议的局限

SSRF 的本质是"让服务器替我发请求"。但发什么请求，取决于协议。

- `http://` —— 只能发 HTTP 报文。打不了 Redis、MySQL、FastCGI。
- `file://` —— 只能读本地文件，出不了这台机器。
- `dict://` —— 能连任意端口，但报文格式被固定成 DICT 协议，只能塞很短的字符串。
- `ftp://` —— 能连任意端口，同样受协议格式限制。
- `gopher://` —— **能连任意 IP:PORT，并发送任意字节流。**

关键在最后一条。Gopher 协议没有任何"报文结构"的约束，
selector 里想放什么就放什么 —— 而 URL 编码 `%0D%0A` 解出来就是 CRLF。

于是 SSRF 从"只能发 HTTP"变成了"能向任意 TCP 端口写任意数据"。
这等于把一个 HTTP 层的漏洞，升级成了传输层的任意写。

### 2.2 一个具体的转换

想给 Redis 发 `GET l3_flag`，Redis 的 RESP 协议长这样：

```
*2\r\n$3\r\nGET\r\n$7\r\nl3_flag\r\n
```

把它整个 URL 编码后塞进 gopher：

```
gopher://redis:6379/_%2A2%0D%0A%243%0D%0AGET%0D%0A%247%0D%0Al3_flag%0D%0A
```

curl 解码后，发到 6379 端口的就是那串原始字节。
Redis 完全不知道对面是个 HTTP 客户端 —— 它只看到合法的 RESP 数组。

这就是 gopher 在 SSRF 里的全部价值：**它是一个字节流注入器。**

### 2.3 一个容易被忽略的限制

libcurl 的 gopher 实现内部走 C 字符串（`strlen`），
所以 payload 里的 NUL 字节（`%00`）会被当成字符串结束符 —— 整条载荷直接变空。

这个限制看起来不起眼，但它决定了"能不能打 MySQL"：

- MySQL 的包长度字段是 3 字节小端，小包的头部必然有 `\x00`
- FastCGI 的 contentLength 是 2 字节大端，同样带 `\x00`

所以用 curl 实现的 SSRF 打 MySQL，是打不通的。
本靶场的 L5/L6 因此换成了 `stream_socket_client` 直发 ——
这个差异不是偷懒，而是真实攻防里必须判断的一件事：
**同一个 SSRF 漏洞，实现方式不同，能打的目标完全不同。**

---

## 三、靶场的威胁模型

### 3.1 一个统一的设定

所有关卡共享同一个前提：

> 有一台能访问内网的 web 服务器，它提供了一个"你给 URL，我帮你取"的接口。

这是 SSRF 最典型的形态 —— 图片代理、URL 预览、Webhook 回调、RSS 抓取、
在线翻译、PDF 生成，全都可以长成这样。

六关的区别只在于**过滤策略**和**目标服务**。

### 3.2 能力链而不是技巧集

六关不是六个孤立的小技巧，而是一条逐级递进的能力链：

```
L1 理解协议 ──→ L2 突破过滤器 ──→ L3 对内网服务说话
                                      │
                                      ├─→ L4 从读到写
                                      ├─→ L5 二进制协议
                                      └─→ L6 不打应用层，直接打运行时
```

每一关只引入一个新变量，其余部分尽量保持不变。
这是刻意设计的 —— 一次只让人卡在一个点上，卡点才清晰。

---

## 四、六关的设计思路

### L1 · Gopher 协议本体

**场景**：内网还有一台 1993 年的老服务没下线，跑在 70 端口。

**设计意图**：把 SSRF、漏洞、利用链全部拿掉，只留下协议本身。

很多人在 SSRF 里第一次见到 gopher，看到的是
`gopher://redis:6379/_%2A2%0D%0A...` 这种天书。
如果一上来就背这个格式，学到的只是"魔法字符串"。
所以第一关直接给一个裸客户端：填 host、port、selector，发出去，看字节。

**考察点**：

- selector 就是一行字符串，末尾 CRLF
- 菜单行的五个 TAB 字段
- type 字符的作用（`0` 文件、`1` 目录、`i` 信息行）
- URL 里的 `/_` 和 `%0D%0A` 是怎么对应到真实字节的

**为什么给一个输入框而不是直接让用户 curl**：
输入框里有 hexdump，能看到"我发的字节"和"收到的字节"。
curl 的 `-v` 虽然也打印，但混在 TLS/HTTP 的调试信息里，不直观。

---

### L2 · 302 换协议

**场景**：运维写了个内部跳转网关，只做 URL 转发，觉得"反正只是拼个链接"。

**漏洞点**：白名单检查的是字符串前缀：

```php
if (strpos($url, 'http://legacy-internal:8081/') !== 0) {
    die('只允许访问内部网关');
}
```

前缀检查本身没错 —— `http://legacy-internal:8081/r?to=...` 确实以它开头。
错在下一步：curl 开了 `CURLOPT_FOLLOWLOCATION` 之后，
**收到 302 会重新发起请求，而新 URL 的协议可以完全不同。**

**设计意图**：介绍"过滤器只校验第一跳"这个经典缺陷。

同类缺陷在真实世界里的形态：

- 只校验 URL 的 host，不校验重定向后的 host（内网穿透）
- 只校验协议前缀，不校验 `Location` 头（协议降级）
- 只校验一次 DNS，实际请求时重新解析（DNS rebinding）

**考察点**：

- 白名单的边界在哪里断掉
- `to` 参数必须二次编码，否则 `:` 和 `/` 会被 URL 解析吃掉
- gopher 的 type `0` 用来读文件

**一个额外细节**：新版 libcurl（7.65+）已经把重定向协议默认限制为
http/https/ftp，所以现代环境下这一关不一定成立。
靶场在 `l2.php` 里显式设了 `CURLOPT_REDIR_PROTOCOLS = CURLPROTO_ALL`，
用来还原老版本行为。这个细节写进了文档，而不是藏着 ——
因为"知道某个技巧在什么版本之后失效"本身就是安全工程的一部分。

---

### L3 · 打 Redis 读 flag

**场景**：内网一台 Redis，没设密码，没绑 127.0.0.1。

**漏洞点**：黑名单只挡了"读本地文件"的协议：

```php
$deny = ['file://', 'dict://', 'ftp://', 'php://', 'data://', 'zlib://'];
```

开发者的威胁模型是"别让人读 /etc/passwd"，所以把 file/dict/php 全禁了。
但 gopher 既不是读文件，也不在名单里 —— 它是"打电话给别人"。

**设计意图**：完成一次思维转换。

前两关的 payload 都是"取回一段内容"，
这一关开始，payload 是**给对方的一条命令**。
gopher 不再是"更灵活的 curl"，而是一个能向内网服务注入指令的通道。

**考察点**：

- RESP 协议：数组形式 `*N` + 每个元素 `$len` + 内容
- `$len` 必须是 key 的**真实字节数**（`l3_flag` 是 7，不是 8）
- 末尾补 `QUIT`，让 Redis 主动断开

**为什么这两个坑值得单独强调**：

第一个坑（`$len` 写错）的表现是"查出来是 nil"，不报错、不异常。
第二个坑（不补 QUIT）的表现是"页面空响应 + 8 秒超时"。

两者都是"静默失败"，靠猜是猜不出来的。
把它们写进关卡说明，是为了让失败有解释，而不是让人怀疑人生。

---

### L4 · 打 Redis 写 WebShell

**场景**：还是那台 Redis，还是同一个注入点。

**设计意图**：同一漏洞的第二种危害。

安全评估里最常见的错误判断是"这个洞只能读不能写，危害有限"。
L4 就是用来打这个判断的：**gopher 注入点没变，只换了 RESP 命令，危害等级从"信息泄露"跳到"远程命令执行"。**

利用链：

```
CONFIG SET dir /var/www/html/uploads
CONFIG SET dbfilename shell.php
SET payload "<?php system($_GET[0]); ?>"
SAVE
```

`SAVE` 会把内存快照写到 `dir/dbfilename`，
而这两个值都是攻击者可控的 —— RDB 文件就成了 webshell。

**考察点**：

- Redis 的"配置项即攻击面"
- RDB 格式前面有一堆二进制垃圾，但 PHP 只在 `<?php` 之后才解析，不影响执行
- 一次 gopher 请求 = 一次 TCP 连接 = 可以连发多条命令

**为什么把 uploads 目录设成 777**：
不是为了让利用变简单，而是因为 Redis 容器里的 `redis` 用户
和 web 容器里的 `www-data` 用户 UID 不一样，
共享目录不给写权限的话，`SAVE` 会失败。
真实环境里的对应条件是"Redis 进程对 web 目录有写权限"，
通常通过共享 volume、NFS、或者干脆 Redis 和 web 跑在同一台机器上实现。

---

### L5 · 打 MySQL 协议包

**场景**：内网 MariaDB，运维图省事建了个免密账号 `ssrf@%`。

**设计意图**：从"应用层文本协议"跨到"二进制协议"。

前三关的 payload 都是可读的 ASCII（RESP、HTTP），
这一关开始，每个字节的位置都有含义：

```
[3 字节小端长度][1 字节序号][载荷]
```

载荷内部：

- `capabilities`（4 字节小端）—— 告诉服务端我支持哪些特性
- `max_packet`（4 字节）
- `charset`（1 字节）
- 23 字节填充
- 用户名 + `\0`
- auth_response 长度（1 字节）+ auth_response

**为什么必须空密码**：

有密码时，认证响应要算：

```
SHA1(pass) XOR SHA1(salt + SHA1(SHA1(pass)))
```

而 `salt` 是服务端在 greeting 包里**每次连接随机生成**的。
gopher 是单向的 —— 发完就等，拿不到 greeting 里的 salt。
所以整个认证包没法离线拼好。

空密码时 `auth_response` 长度为 0，不需要 salt，
整个字节流才能一次性构造。**这是这条路唯一的硬限制，不是设计上的偷懒。**

**考察点**：

- 二进制协议的字段对齐
- 序号（seq）的语义：认证阶段递增，命令阶段重置为 0
- 为什么用 `stream_socket_client` 而不是 curl（NUL 截断，见 2.3）

**一个实践中的坑**：手工一次性连发 `HandshakeResponse(seq=1)` + `COM_QUERY(seq=0)`
是可行的，但顺序不能颠倒，也不能中间插 `COM_QUIT` 到错误位置。
如果服务端回 `Got packets out of order`，八成是 seq 用错了。

---

### L6 · 打 PHP-FPM 的 FastCGI

**场景**：web 架构是 nginx + php-fpm，fpm 监听 9000。

**设计意图**：绕过应用层，直接打运行时。

前五关打的都是"应用"（Redis 的配置、MySQL 的查询）。
这一关打的是 **PHP 解释器本身** —— 请求根本不经过 nginx，
不经过任何 PHP 代码的路由逻辑，直接以 fpm worker 的身份执行。

这是 SSRF 危害等级的上限：不是"读到了什么"，而是"拿到了这个进程的 shell"。

**利用原理**：

FastCGI 的记录格式是 8 字节头 + 内容：

```
[version=1][type][requestId:2][contentLength:2][padding:1][reserved:1]
```

三条记录构成一个最小请求：

- `type=1` BEGIN_REQUEST —— role=1（RESPONDER）
- `type=4` PARAMS —— 环境变量
- `type=5` STDIN —— 请求体

核心在 PARAMS 里的这两个：

```
SCRIPT_FILENAME = /var/www/html/index.php
PHP_VALUE       = auto_prepend_file=php://input
```

`auto_prepend_file` 是 `PHP_INI_PERDIR` 级别，可以被请求级覆盖。
fpm 在执行 `index.php` 之前，会先把 `php://input`
（也就是 STDIN 里的内容）include 进来 —— 那就是我们的 PHP 代码。

**考察点**：

- FastCGI 记录的拼接
- name-value 对的编码顺序（**两个长度字段连着放**，见下）
- 为什么 9000 端口暴露等于 RCE

**这一关最狠的坑**：

FastCGI 的 name-value 对编码是：

```
nameLen(1) + valueLen(1) + name + value
```

不是直觉上的 `nameLen + name + valueLen + value`。
写错的话，fpm 会把 value 长度当成 name 的第一个字节去解析，
然后**直接把 TCP 连接 RST 掉** —— 页面上只显示"空响应"，
fpm 日志里一行记录都没有。

定位方法（也是排查这类问题的通用方法）：
用标准客户端 `cgi-fcgi` 打一个记录字节的 sink，把标准 payload 存下来，
再和自己拼的用 `cmp -l` 逐字节对比。

---

## 五、关卡之间的技术递进

按"新增变量"排列，每一关只比上一关多一个难点：

- **L1** 协议是什么 —— 新增：selector 与 CRLF
- **L2** 怎么绕过过滤器 —— 新增：重定向跨协议
- **L3** 怎么对内网服务下命令 —— 新增：RESP 编码 + 连接生命周期
- **L4** 怎么从读变写 —— 新增：配置项即攻击面
- **L5** 怎么处理二进制协议 —— 新增：字段对齐 + 认证前提
- **L6** 怎么绕过整个应用层 —— 新增：FastCGI 记录 + INI 覆盖

横向看，六关覆盖了四类内网目标：

- 缓存/键值（Redis）—— 文本协议，配置可写
- 数据库（MySQL）—— 二进制协议，需要认证
- 运行时（PHP-FPM）—— 二进制协议，无认证
- 传统服务（Gopher）—— 文本协议，无认证

这四类基本覆盖了 SSRF 在内网横向时的常见目标。

---

## 六、设计上的取舍

靶场为了聚焦某个知识点，故意放宽了一些条件。
这些取舍都写在这里，而不是藏在代码里 —— 因为**知道"真实环境不是这样"比知道"这里能打通"更重要**。

### 6.1 L5 的免密账号

真实环境里 MySQL 几乎不会允许空密码远程登录。
这一关的前提是"运维图省事建了个 `ssrf@%` 免密账号" —— 这种事在
内部测试环境、临时排查环境里确实会发生，但不能当常态。

如果目标是真实的有密码 MySQL，gopher 这条路基本走不通（见 L5 关于 salt 的说明）。
更现实的替代路径是：先用别的方式拿到配置文件的密码，
再用能双向通信的 SSRF（比如 `gopher` + 自定义客户端）完成认证 —— 但那就不是 gopher 的故事了。

### 6.2 L6 的 `allow_url_include=On`

PHP 默认是 `Off`。真实环境中要打 FastCGI，通常需要满足以下之一：

- 目标环境已经开了 `allow_url_include`（罕见但存在）
- 配合任意文件写入，把 `auto_prepend_file` 指向一个已存在的本地文件
- 利用 `PHP_ADMIN_VALUE` 改其他配置（受 `disable_functions` 等影响）

靶场直接开了，是为了把注意力集中在"拼 FastCGI 包"本身。
这个前提在 `fpm/Dockerfile` 和页面说明里都标注了。

顺便一个知识点：`allow_url_include` 是 `PHP_INI_SYSTEM` 级别，
`PHP_VALUE` 改不动 —— 所以不能靠 FastCGI 请求自己把它打开。
必须在 php.ini 或 `-d` 里设。

### 6.3 Redis 7 的 protected config

Redis 7.0 引入了 `enable-protected-configs`，
把 `dir` / `dbfilename` / `appendfilename` 归为 protected config，
`CONFIG SET` 默认被拒绝（取值为 `no`）。

这意味着 **L4 的利用在 Redis 7.0+ 上默认失效**，
需要服务端显式设置 `--enable-protected-configs yes` 才能还原老行为。

靶场启动参数里加了这一项，并在 `README.md` 和 `compose.yml` 注释里都写明了。
现实中的替代路径包括：写 crontab（如果 Redis 有权限）、
主从复制 RCE（Redis 4.x/5.x）、加载恶意 module（Redis 5.0+，需要 `MODULE LOAD` 权限）。

### 6.4 L2 的重定向协议限制

前面提过：libcurl 7.65+ 默认把 `REDIR_PROTOCOLS` 限制为 http/https/ftp。
靶场显式放开，是为了让"跨协议重定向"这个知识点可演示。

真实环境里要判断两件事：目标用的 curl 版本，以及代码有没有显式设置这个选项。

---

## 七、实现上的几个决定

### 7.1 为什么自己写 Gopher 服务端

`pygopherd` 之类的现成实现功能齐全，但对这个靶场来说是负担：

- 配置项多，启动一个最小实例要写一堆配置
- 行为不透明，看不到"selector 进来、字节出去"的过程
- 不好控制返回内容的边界（比如 `.\r\n` 结束符）

自己写的 `legacy/server.py` 只有 200 行左右，逻辑是：

```
收到一行 → 判断是不是菜单 → 是就拼菜单，不是就读文件 → 吐出内容 + .\r\n
```

好处是**每个字节都可解释**。L1 的页面里那个 hexdump，
对照的就是这段代码。

### 7.2 两种 SSRF 实现，故意并存

`src/common.php` 里有两个取 URL 的函数：

- `http_fetch()` —— 用 curl，走 libcurl 的 gopher 实现
- `gopher_socket()` —— 用 `stream_socket_client`，原始 TCP

L2/L3/L4 用前者，L5/L6 用后者。

这不是实现不一致，而是刻意保留的对比：
**同一个漏洞，实现方式不同，能打的目标就不同。**
curl 版本会被 NUL 截断，socket 版本不会 —— 这个差异本身就是一个知识点，
所以在页面说明、README、这份文档里各讲了一遍。

### 7.3 flag 的存放方式

- L1/L2：作为文件放在 gopher 服务的资料目录里，通过协议本身读出来
- L3：作为 Redis 的 key，启动时由 `setup.sh` 写入
- L4：挂在 web 容器的 `/flag_l4`，需要 webshell 才能读
- L5：存在 MariaDB 的 `secret.flag` 表里
- L6：挂在 fpm 容器的 `/flag_l6`

每关的 flag 位置都对应"这一关拿到的东西"：

- 拿到文件读取能力 → 读文件
- 拿到命令执行 → 读文件系统
- 拿到数据库查询 → 读表

不给"万能 flag"，是因为**flag 的位置本身就是对利用深度的说明**。

### 7.4 目录结构

```
compose.yml        六个容器
Dockerfile         web（PHP 8.1 + Apache）
setup.sh           一键起 + 灌 flag
src/               六关页面 + common.php
legacy/            gopher 服务 + 302 网关（Python stdlib）
fpm/               裸 php-fpm（故意不带 nginx）
db/init.sql        L5 的库表和免密账号
poc/               参考利用脚本
flags/             六关答案
```

`legacy/server.py` 和 `poc/*.py` 都是纯标准库，不依赖任何第三方包 ——
这样换个环境（比如同学机器、比赛现场）也能直接跑。

---

## 八、打完之后的延伸

### 8.1 防御视角

如果要从防守方角度看这个靶场，值得关注的点：

- **SSRF 的过滤不能只做字符串前缀**。正确做法是解析 URL、校验 host 解析后的 IP 是否在允许网段，且**每一跳都校验**。
- **禁用危险协议**。curl 有 `CURLOPT_PROTOCOLS` 和 `CURLOPT_REDIR_PROTOCOLS`，显式设成 `CURLPROTO_HTTP | CURLPROTO_HTTPS`。
- **内网服务不要裸奔**。Redis 绑定 127.0.0.1 + requirepass；MySQL 不用免密账号；php-fpm 只监听 unix socket 或 127.0.0.1。
- **出网限制**。web 服务器到内网的访问应该有明确的白名单，而不是"能连就能连"。

### 8.2 还想继续深入的方向

- **Redis 主从复制 RCE**：`SLAVEOF` + 恶意模块，适用于 Redis 4.x/5.x，不依赖文件写入
- **Gopher 打 FastCGI 的变体**：不用 `php://input`，改成 `data://` 或 `php://filter`
- **DNS rebinding**：绕过基于域名/IP 的校验
- **gopher 打其他服务**：Memcached、Zabbix、Docker API、Jenkins、SMTP

---

## 附：一句话总结每关

- L1 —— 协议只有一行，难的是承认它这么简单
- L2 —— 过滤器校验的是第一跳，而请求会走第二跳
- L3 —— gopher 不是"更灵活的 curl"，是"给内网服务下命令的通道"
- L4 —— 同一个洞，从读变写，危害等级就换了一档
- L5 —— 二进制协议里，每个字节都要对得上，包括那个 0x00
- L6 —— 绕过整个应用层，直接和解释器说话
