# Gopher 靶场

六关，从 RFC 1436 协议本体一路打到用 gopher 完成 RCE。

所有后端服务都在容器内网，宿主机连不到 —— 想打就得借 web 那台机器的手。
这正是 gopher 在 SSRF 里值钱的原因：它能连**任意 IP:PORT** 并逐字节发送数据。

## 快速开始

```bash
./setup.sh          # 铺 flag、建目录、构建、启动、灌数据
open http://127.0.0.1:8896/
```

停止：

```bash
docker compose down
```

重置（flag 会被重新灌回去）：

```bash
./setup.sh
```

## 架构

```
        宿主机浏览器 :8896
             │
      ┌──────▼───────┐
      │   web (PHP)  │   ← 六关的 SSRF 入口都在这里
      └──┬───┬───┬───┘
         │   │   │
    ┌────▼┐ ┌▼───┐ ┌▼────┐
    │redis│ │ db │ │ fpm │   L3/L4   L5   L6
    │6379 │ │3306│ │9000 │
    └─────┘ └────┘ └─────┘
         │
    ┌────▼─────────────┐
    │ legacy-internal  │  gopher:70 + http:8081      L2
    └──────────────────┘
    ┌──────────────────┐
    │ legacy-public    │  gopher:70（宿主机 7070）   L1
    └──────────────────┘
```

## 关卡

| 关卡 | 目标 | 关键点 | flag 在哪 |
|---|---|---|---|
| L1 Gopher 协议本体 | `legacy-public:70` | 只有一行 selector + CRLF；菜单行的五个 TAB 字段 | 服务端资料目录 |
| L2 302 换协议 | `legacy-internal:8081` | 白名单只管前缀；curl 跟随重定向时不校验新协议 | `legacy-internal:70` 里 |
| L3 打 Redis 读 | `redis:6379` | 黑名单漏了 gopher；RESP 数组格式 | key `l3_flag` |
| L4 打 Redis 写 | 同上 | `CONFIG SET dir/dbfilename` + `SAVE` | web 容器 `/flag_l4` |
| L5 打 MySQL | `db:3306` | 手工拼 HandshakeResponse41 + COM_QUERY | `secret.flag` 表 |
| L6 打 PHP-FPM | `fpm:9000` | FastCGI 记录 + `PHP_VALUE auto_prepend_file` | fpm 容器 `/flag_l6` |

参考脚本在 `poc/`，从 `01` 到 `06` 按顺序。**建议先自己调通再看**。

```bash
cd poc
python3 01_gopher_raw.py
python3 02_redirect_302.py
python3 03_redis_read.py
python3 04_redis_webshell.py
python3 05_mysql_gopher.py
python3 06_fastcgi_gopher.py
```

## 六个坑（都是实际的坑，不是装饰）

**1. RESP 的 `$<len>` 必须是真实字节数**
`l3_flag` 是 7 字节。写成 `$8`，Redis 会把结尾的 `\r` 当成 key 的一部分，
`GET` 出来永远是 nil，而且不报错 —— 最难受的那种失败。

**2. 打 Redis 一定要补 `QUIT`**
Redis 默认不主动关连接。不补 QUIT，curl 会一直等到超时然后返回 `false`，
把已经收到的数据全丢掉。补一条 QUIT，连接正常关闭，响应就回来了。

**3. curl 的 gopher 实现遇到 `%00` 会截断**
libcurl 内部走 C 字符串（`strlen`），payload 里的 NUL 就是结束符。
MySQL 的 3 字节长度字段、FastCGI 的 2 字节 contentLength 几乎必然带 NUL ——
所以 L5/L6 的接口改成了 `stream_socket_client` 直发。
真实攻防里「能不能打 MySQL」往往就取决于 SSRF 是怎么实现的。

**4. FastCGI 的 name-value 对是两个长度字段连着放**
```
nameLen(1) + valueLen(1) + name + value
```
不是「名字长度 + 名字 + 值长度 + 值」。拼错的话 fpm 直接把连接 RST 掉，
页面上只看到「空响应」，日志里干干净净 —— 我在这卡了很久。

**5. php-fpm 默认可能只监听 IPv6**
`listen = 9000` 会被解析成 `[::]:9000`，从别的容器用 IPv4 连直接 RST。
靶场的 `fpm/Dockerfile` 里显式写了 `listen = 0.0.0.0:9000`。

**6. Redis 7 的 protected config**
`CONFIG SET dir` / `dbfilename` 在 Redis 7 默认被禁，需要
`--enable-protected-configs yes`。老版本（≤6.2）没有这道闸，
所以 L4 的利用在老环境上是直接成立的。

## 设计上的一些取舍

- **L5 的账号是空密码**。有密码就要算 `SHA1(pass) XOR SHA1(salt + SHA1(SHA1(pass)))`，
  而 salt 每次连接随机 —— gopher 只发不收，拿不到。这是硬限制，不是偷懒。
- **L6 的 fpm 开了 `allow_url_include=On`**。真实环境默认 Off，
  需要配合任意文件写入（比如 L4 的 webshell）才能把 `auto_prepend_file`
  指到可执行内容上。这里直接开，是为了把注意力集中在拼包上。
- **L2 故意放开了 `CURLOPT_REDIR_PROTOCOLS`**。新版 libcurl 默认已把重定向协议
  限制在 http/https/ftp，L2.php 里显式设成 `CURLPROTO_ALL` 来模拟老版本行为。

## 目录结构

```
compose.yml          六个服务
Dockerfile           web（PHP 8.1 + Apache）
setup.sh             一键起 + 灌 flag
src/                 六关的页面和共用函数
legacy/              gopher + 内部 HTTP 网关（Python stdlib）
fpm/                 裸 php-fpm
db/init.sql          L5 的库表和免密账号
poc/                 参考利用脚本
flags/               六关答案（自己核对用）
```

## 目录

- `src/common.php` — 页面骨架、`http_fetch()`（curl）、`gopher_socket()`（原始 TCP）
- `src/l1.php` … `l6.php` — 每关的说明和注入点
- `legacy/server.py` — RFC 1436 的最小实现，顺便带一个 302 网关
