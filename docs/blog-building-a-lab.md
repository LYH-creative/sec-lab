---
title: 从七个零散靶场到一条 docker compose up：我的安全练习环境搭建全记录
published: 2026-10-27
description: 把七个各自独立的漏洞靶场合并成一个可分发仓库的完整过程，包括架构取舍、六个真实踩坑，以及一个把边框画到文字上的 CSS bug。
tags: [Docker, 安全, 靶场, 踩坑]
category: 技术
draft: false
---

# 从七个零散靶场到一条 `docker compose up`

今年陆续搭了七个靶场，一直是"一个目录一套 compose"，想练哪个就进对应目录敲 `./setup.sh`。等到第七个做完，我发现自己记不住端口了——8890 是 PHP 8.1 的反序列化，8891 是 PHP 7.4 的，8894 是……不，那是空的。

更麻烦的是想给别人用。发一个仓库链接过去，对方要 clone 七次、看七份 README、记七个端口。所以我花了一段时间把它们合并成一个仓库，目标是**陌生人 clone 下来，两条命令就能打开浏览器开始练**。

这篇文章记录整个过程：设计取舍、合并时的架构问题、以及六个把我卡住的坑。最后那个坑尤其值得说——它让我一度以为编码坏了。

---

## 一、先定骨架：七个靶场怎么选

一开始是按"漏洞类型"一个个加的，很快就发现问题：DVWA 已经覆盖了 SQL 注入、XSS、文件上传、命令执行，我再单独做一个 SQL 注入靶场纯属重复劳动。

于是改成按**攻击链的环节**来排，每个靶场负责一个阶段：

- **DVWA** — 基础面。Web 常规漏洞都在这里打地基，不重复造轮子
- **反序列化** — 代码执行。PHP 和 Java 两条线，因为两边的坑完全不同
- **XXE** — 解析器层面的输入处理
- **Gopher** — SSRF 的深水区。协议层手工拼包
- **JWT** — 认证与签名。同一套代码的四个单点差异
- **webshell-hunt** — 反过来。已经失守的服务器，练排查
- **ARP** — 网络层。唯一一个跑在链路层、需要特权的实验

最终是 **7 个靶场、19 个容器、36 个关卡/后门/实验**。

<!-- 图：导航页首页截图 -->

---

## 二、七个靶场的设计取舍

这一段不是教程，是每个靶场"为什么这么做"的记录。具体玩法在各目录的 README 里。

### 2.1 DVWA：不重复造轮子

DVWA 有 18 个漏洞模块，每个都能在 low / medium / high / impossible 四档之间切换看源码差异。这个"四档对比"的价值比我自己写十个靶场都高——同一个注入点，防护从无到有，代码差在哪，一眼能看见。

所以我只做了两件事：用官方镜像，配一个独立的 MariaDB。配套写了个 `setup_dvwa.py` 自动点"Create / Reset Database"按钮（要带 CSRF token，所以得先 GET 拿 token 再 POST，还得用 CookieJar 保持同一个 session）。

### 2.2 反序列化：为什么非要三个容器

这一套要三个容器，不是为了好看：

- **PHP 8.1** — L1 魔术方法、L2 POP 链、L3 private 属性
- **PHP 7.4** — L4 的 phar
- **JDK 8** — Java 原生反序列化

phar 单独跑 7.4，是因为**触发点在 8.x 上已经失效**。PHP 7.4 里 `file_exists`、`is_file`、`filesize`、`md5_file` 碰到 `phar://` 路径就会反序列化 metadata；PHP 8.1 改成了惰性反序列化，这些函数全部不再触发，只有显式 `new Phar()->getMetadata()` 才会。

如果硬要在一个 8.1 容器里演示 phar，要么利用链不成立，要么得编一个"显式调用 getMetadata"的假场景。我宁愿多起一个容器保持真实。

同样在这里踩过的坑：网上流传的"属性数写大绕过 `__wakeup`"（CVE-2016-7124）在 PHP 8.1 上**直接让 `unserialize()` 返回 false**，对象根本不创建。`O:5:"Gate":99:{...}` 这种 payload 抄来就是浪费半小时。

### 2.3 XXE：五关递进的依据

五关不是随便加的，是按"回显能力"递减排的：

1. 有回显 → 直接读 `/flag`
2. 无回显但能出网 → 外部 DTD 外带
3. 无回显也不许出网 → 报错型
4. 有回显但目标是内网 → XXE 转 SSRF
5. 上传点本身是 XML（SVG）→ 入口不同

每一关都对应真实环境里的一种限制条件。做完这五关，看到 XML 解析点会本能地问：回显吗？出网吗？目标在哪？

建这一套时最硬的坑是 L3：报错型 payload **不能写在内部子集里**。XML 规范明确禁止内部子集的实体声明值中出现参数实体引用，libxml 直接报 `PEReferences forbidden in internal subset in Entity`。我一开始以为是自己拼接写错了，翻了规范才知道这条路根本走不通，必须落到外部 DTD（本地 `file://` 或远程 `http://`）。

### 2.4 Gopher：把协议层单独拎出来

SSRF 的教程大多停在"打个内网 80 端口看看"。但 SSRF 真正值钱的地方是 `gopher://`——它能连任意 IP:PORT 并逐字节发送数据，等于一个**字节流注入器**。

六关从协议本体一路打到 RCE：

- L1 纯 gopher，看清 selector 和 CRLF
- L2 白名单 + 302 换协议
- L3 打未授权 Redis 读 key
- L4 同一个洞，`CONFIG SET dir` + `SAVE` 写 webshell
- L5 手工拼 MySQL 的 `HandshakeResponse41` + `COM_QUERY`
- L6 手工拼 FastCGI 记录，`PHP_VALUE` 改 `auto_prepend_file`

L5 用了免密账号，不是偷懒。有密码就要算 `SHA1(pass) XOR SHA1(salt + SHA1(SHA1(pass)))`，而 salt 每次连接随机——gopher 只能发不能收，拿不到 salt。这是协议的硬限制。

### 2.5 JWT：同一段代码，四个单点差异

四关共用一套后台代码，每关只改一个实现细节：弱密钥、`alg:none`、RS256→HS256 算法混淆、`kid` 路径穿越。

这样设计的好处是差异足够小，小到只能靠读代码发现。比如 L3 的问题出在两行：

```php
if ($alg === 'HS256') {
    $ok = hash_equals(sign_hs256($input, $pub), $s);  // 公钥当 HMAC 密钥
} else {
    $ok = openssl_verify($input, b64u_decode($s), $pub, OPENSSL_ALGO_SHA256) === 1;
}
```

公钥就挂在页面上让人下载。人手一把签名密钥。

L4 选 `../../../../dev/null` 而不是 `/etc/passwd`，是因为它一定存在、一定可读、内容为空——而空字符串恰好是 `hash_hmac` 能接受的密钥。用 passwd 也能打，但内容长度不定，不好复现。

### 2.6 webshell-hunt：反过来出题

前面六个都是"从外部打进去"。这个反过来：给你一台**已经被入侵**的服务器，9 处后门藏在 25 个文件里，还有 1 处诱饵专门检验会不会误报。

评价标准不是"找到 flag"，是**别漏，也别误报**。诱饵 `admin-ajax.php` 里那句 `call_user_func( $handlers[ $action ] )` 长得很像后门，但 `$action` 被白名单限制，属于正常分发逻辑。报它就说明规则校准不到位。

这关的容器构建脚本里有一堆 `chown` 和 `touch -d`，因为后门的**权限位、属主、mtime 都是证据**。比如 `functions.php` 明明有后门，但 mtime 被改回了安装时间，纯时间线排查抓不到它——这个细节是刻意留的。

### 2.7 ARP：唯一需要特权的那个

三容器同 bridge：网关 `172.28.0.2`、受害者 `172.28.0.3`、攻击机 `172.28.0.4`。都带 `NET_ADMIN` + `NET_RAW`，攻击机额外开 `net.ipv4.ip_forward=1`。

`ip_forward` 必须写在 compose 的 `sysctls` 里，进容器后再 `sysctl -w` 会被拒——它属于要在创建 netns 时就定好的参数。

七个实验从"为什么 arpspoof 跑了没反应"开始。这个坑很典型：单向毒化只骗了受害者，攻击机自己不转发，于是流量到了攻击机就断了。很多人以为毒化失败，其实是没开转发。

---

## 三、合并：从七个仓库到一个编排

七个靶场各自能跑之后，合并才是真正的工程活。这里有几个必须做的决定。

### 3.1 为什么不用 `include`

Docker Compose 2.20+ 支持 `include`，可以把子目录的 compose 文件直接引进来。看起来很省事，我最后没用，原因有三个：

- 每个子 compose 有自己的 `name:`，include 之后项目名前缀会变，`container_name` 和网络归属容易乱
- 端口、日志、重启策略要统一调整，分散在七个文件里改起来容易漏
- `include` 有最低版本要求，别人 clone 下来可能直接跑不起来

最终写了一个显式的 `docker-compose.yml`，所有服务列在一起。代价是有重复，好处是**一个文件就是完整真相**。

### 3.2 每个靶场一个网络（以及为什么）

最开始的版本图省事，所有服务挂在同一个 bridge 上。测试时发现一个问题：XXE 的 L4 要求打内网服务 `internal`，但因为所有靶场同网，SSRF 顺手就能摸到隔壁的 DVWA 和 Redis。

关卡边界就这么没了。

改成**一个靶场一个 bridge**：

```yaml
networks:
  portal-net:
  dvwa-net:
  deser-net:
  xxe-net:
  gopher-net:
  jwt-net:
  hunt-net:
  arp-net:
    driver: bridge
    ipam:
      config:
        - subnet: 172.28.0.0/24
```

`xxe-web` 只能看到 `xxe-internal`，`gopher-web` 只能看到它自己的 `redis` / `db` / `fpm`。SSRF 打出去的目标是确定的。

### 3.3 network alias：让源码一行都不用改

合并时最麻烦的事：各靶场源码里把 hostname 写死了。

```
gopher/src/l3.php:   gopher://redis:6379
gopher/src/l5.php:   gopher://db:3306
gopher/src/l6.php:   gopher://fpm:9000
xxe/src/l4.php:      http://internal/admin.php
gopher/poc/*.py:     legacy-internal:8081
```

而 compose 里服务名不能重复——`dvwa` 有个 `db`，`gopher` 也有个 `db`。加前缀是必须的，但加完前缀，上面这些全都会解析失败。

解法是 **network alias**：

```yaml
gopher-redis:
  networks:
    gopher-net:
      aliases:
        - redis
```

服务名叫 `gopher-redis`（避免冲突），但在 `gopher-net` 这个网络里同时拥有 `redis` 这个别名。于是源码和 poc 脚本一行都不用改，`redis:6379` 照样能解析。

这是个很小的技巧，但省掉了几百处修改，也避免了改错。

### 3.4 ARP 用 profile 隔离

它不是 Web 靶场，跑完就该关掉；而且需要 `NET_ADMIN` / `NET_RAW`，某些环境的安全策略会拦。

所以放进 `profiles: ["net"]`，默认 `docker compose up -d` 不会启动。要用的时候：

```bash
./lab.sh up all
```

### 3.5 端口规划

原来七个靶场的端口是散的（有的 8888，有的 8896），合并时统一到 8880–8899 一段，外加 Gopher L1 的 7070。

所有端口都写成：

```yaml
ports:
  - "${LAB_BIND:-127.0.0.1}:8888:80"
```

默认绑回环。想从局域网访问就 `LAB_BIND=0.0.0.0 ./lab.sh up`——但文档里我明确写了警告：**这些容器里有真实的命令执行漏洞，绑 0.0.0.0 等于把 DVWA 的 RCE 送给整个网段**。

---

## 四、踩坑实录

这一段是这篇文章里最值得看的部分，因为每一个都真实卡过我。

### 4.1 嵌套 `.git`：GitHub 上目录是空的

`deserialization/` 原本是个独立仓库，有自己的 `.git` 和 remote。合并到顶层仓库时，`git add .` 看起来一切正常，但如果直接推送，GitHub 上那个目录会是**一个空的灰色图标**——顶层 git 把它当成了 submodule（gitlink），只记录一个 commit hash，不包含任何文件。

对方 clone 下来，`deserialization/` 是空的，`docker compose up` 直接报找不到 Dockerfile。

我用的处理是**可逆的**：把 `.git` 改名成 `.git.archive`，加进 `.gitignore`。

```bash
mv deserialization/.git deserialization/.git.archive
```

这样顶层能完整跟踪这个目录的所有文件，原来的提交历史也还在本地，想恢复独立仓库随时改回来。

> 如果那个历史需要保留到新仓库里，正确做法是 `git subtree add` 或 `git filter-repo` 合并历史。我这里选择归档，是因为那些提交记录本来就只是这个子目录的，合进来反而让历史变乱。

### 4.2 容器名冲突

因为每个服务都写了固定的 `container_name`（`xxe-web`、`jwt-web`……），以前用单靶场模式起过的容器即使已经 `Exited`，名字仍然被占用。集成版一启动就报：

```
Error response from daemon: Conflict. The container name "/xxe-web" is already in use
```

第一次遇到时我手动 `docker rm -f` 了十几个容器。但这不是"我能解决"就够的事——别人也会遇到。所以在 `lab.sh` 里加了预检：

```bash
for n in $ALL_CONTAINERS; do
    docker container inspect "$n" >/dev/null 2>&1 || continue
    proj=$(docker inspect -f '{{index .Config.Labels "com.docker.compose.project"}}' "$n")
    [ "$proj" = "sec-lab" ] && continue      # 自己的不动
    docker rm -f "$n"                        # 别人的同名容器清掉
done
```

判断依据是 compose 项目的 label，只删不属于当前项目的同名容器，不会误伤自己的。

### 4.3 172.28 网段被占

ARP 靶场的 IP 在脚本里写死了 `172.28.0.0/24`。启动时报：

```
Error response from daemon: invalid pool request:
Pool overlaps with other one on this address space
```

原因是旧项目的网络 `arp-lab_arpnet` 还在，占着这个网段。容器删了，网络不会自动删。

这个也写进脚本了，顺手清掉旧靶场项目的遗留网络。

> 根治办法是改网段。但那要同时改 `arp/scripts/*.py`、README 里的所有 IP、以及原理文档——为了一个只在开发机上出现的冲突不值得。所以我选择在脚本里处理，并把这个问题写进 FAQ。

### 4.4 poc 脚本的两个假阳性

这两个都不影响靶场本身，但会让人误以为"打不通"，危害比真 bug 还大。

**第一个：重定向的 0 字节窗口。**

Java 反序列化的验证脚本是先 POST payload，再从 `/static/flag.txt` 读结果。命令是 `cat /flag > /tmp/out/flag.txt`。

shell 执行重定向时会**先打开文件并截断**（变成 0 字节），再写入内容。POST 返回后立刻 GET，有概率正好命中"已创建但还没写完"的窗口，读到空字符串。

表现是**偶发失败**——我第一次跑成功了，第二次失败，第三次又成功。这种时好时坏最容易让人怀疑环境。

修复是轮询到有内容为止，而不是读一次就完：

```python
def get_settled(path, tries=20, delay=0.1):
    text = ''
    for _ in range(tries):
        text = get(path)
        if text.strip():
            return text
        time.sleep(delay)
    return text
```

改完连跑三次都稳定。

**第二个：RDB 里的前一个 flag。**

Gopher L4 是往 Redis 写 webshell，然后访问 `/uploads/shell.php?0=cat /flag_l4` 读 flag。

脚本从响应里正则提取 `flag{...}`。但响应体的**前面是整段 Redis RDB 快照**——而我 L3 步骤往 Redis 里 SET 过 `l3_flag`，值以明文存在 RDB 里。

于是 `re.search` 命中的第一个是 **L3 的 flag**，脚本报告"打穿了"，但打出来的是上一关的答案。我一度以为是 L4 没成功。

看了一眼原始响应才发现里面有两个 flag：

```
flag{r3d1s_un4uth_r3ad_4ll_k3ys}    ← RDB 快照里的
flag{r3d1s_wr1t3s_y0ur_w3bsh3ll}    ← system() 执行出来的
```

`system()` 的输出在响应末尾，所以取**最后一个**才对。

### 4.5 `<a>` 标签的边框画在了文字上

这个坑最离谱，因为它看起来像编码坏了。

Gopher 靶场首页的关卡列表，每张卡片的**描述行开头几个字是糊的**，像一堆乱码符号：

```
L2 · 302 换协议  WHITELIST
^'"'"' 访问内部 HTTP 网关，但网关自己会 302 到 gopher
```

原文应该是"只允许访问内部 HTTP 网关"。

我的第一反应是编码问题，于是按顺序排除了：

- `curl` 拿到的字节：`e6b2a1 e69c89`，就是标准 UTF-8 的"没有"
- 带 gzip（浏览器真实请求）：`curl --compressed` 结果一样正确
- DOM：`--dump-dom` 解析出来的文本完全正常
- Unicode 码点：六个 `desc` 全是 CJK 统一汉字（`6CA1 6709`、`53EA 5141 8BB8`）
- 转义函数：`h()` 就是 `htmlspecialchars($s, ENT_QUOTES, 'UTF-8')`
- 字体：`body` 指定了 PingFang SC，对比度也够

所有环节都对，但渲染出来就是错的。

转折点是做了个最小复现：同样的 CSS、同样的文字，只把容器标签从 `<a class="card">` 换成 `<div class="card">`——**完全正常**。

差别在默认 `display`。`<a>` 是 **inline** 元素，而 `.card` 的样式里只写了背景、边框、圆角，**漏了 `display: block`**：

```css
.card {
  background: var(--panel);
  border: 1px solid var(--line);
  border-radius: 10px;
  padding: 16px 18px;
}
```

inline 元素的边框不会像块级元素那样包住整个矩形，而是**每行文字的首尾断开重新绘制**。那条左边框正好落在描述行的第一个字上，和文字叠在一起——远看就是一团乱码。

注释里我写得很直白：

```css
.card {
  /* 卡片在 HTML 里是 <a>，而 <a> 默认是 inline。
     不显式转成 block 的话，边框/背景会按 inline 盒绘制：
     每一行文字的首尾都会断开重绘，边框正好压在描述行的行首，
     看起来像一堆乱码（Windows/Mac 都一样，不是字体问题）。 */
  display: block;
}
```

一行修好。

这个坑的教训是：**当"数据全对但显示不对"时，先怀疑布局模型，再怀疑编码**。我按编码方向查了十几分钟，方向从一开始就偏了。

---

## 五、交付：让陌生人能一键跑起来

### 5.1 `lab.sh` 干了什么

`docker compose up` 本身不够。这套环境里有一堆"启动前必须做"和"启动后必须做"的事：

**启动前：**

- 三个靶场的 `uploads` 目录要 `chmod 777`（容器里的 `www-data` 和 `redis` 要往里写）。clone 下来默认 755，不放开的话签名、上传类的关卡会静默失败
- JWT 的私钥在宿主机上是 600，bind mount 进去 `www-data` 读不到，`openssl_sign` 会**静默签出空签名**——令牌长得完全正常，只是签名段是空的
- Gopher 的两个 flag 要复制到只读挂载的目录里

**启动后：**

- Gopher L5 的 flag 要写进 MySQL，L3 的写进 Redis
- DVWA 要自动点一次"建库"

所以 `lab.sh` 把这些串起来，默认跑完就打印入口表。

有个细节值得一提：等 MariaDB 就绪**不能用** `mariadb-admin ping`。它在初始化还没结束的时候就能连上，那时 root 密码还没落库，紧接着执行 INSERT 会 `Access denied`。要用真正的查询探测：

```bash
docker exec gopher-db mariadb -uroot -proot123 -e 'SELECT 1'
```

### 5.2 答案文档的分寸

`docs/answers.md` 里有全部 16 个 flag。有人会问：靶场把答案写出来还有什么意义？

我的考虑是：

- flag 本来就是写在仓库里的（`flags/*.flag`），藏不住
- 真正的价值在**思路**：为什么这么打、卡在哪、怎么绕过去
- 文档开头明确写了"先自己做，卡住两小时以上再看"

而且每关的答案都写成"关键点 + 坑"，不是直接贴 payload。比如 Gopher L3 那条，重点不是 `gopher://redis:6379/_...` 这个 URL，而是 **RESP 里的 `$<len>` 必须是 key 的真实字节数**——`l3_flag` 是 7 字节，写成 8 会把结尾的 `\r` 吃进 key 里，查出来永远是 nil 且不报错。

---

## 六、现在它长什么样

```
sec-lab/
├── docker-compose.yml     # 19 个容器，一个文件
├── lab.sh                 # up / down / init / reset / status / answer
├── README.md              # 部署、端口表、FAQ
├── docs/answers.md        # 全部 flag 和思路
├── portal/html/           # 导航页（8880）
├── dvwa/
├── deserialization/
├── xxe/
├── gopher/
├── jwt/
├── webshell-hunt/
└── arp/
```

用起来是这样：

```bash
git clone <仓库地址> sec-lab
cd sec-lab
chmod +x lab.sh
./lab.sh up
```

然后打开 `http://127.0.0.1:8880/`。

<!-- 图：导航页 / 启动输出截图 -->

每个靶场目录里仍保留着自己的 `compose.yml`，可以单独起——调试某一关时更快。代价是容器名和集成版一样，同时开会冲突，文档里写明了先 `./lab.sh down`。

---

## 七、还没解决的问题

写出来比藏着有用：

- **首次构建慢**。要拉 nginx、mariadb、redis、python、php 多个基础镜像，Java 镜像还要从 Maven Central 下 jar。网络不好时 10 分钟起步。
- **XXE 的盲打和外带依赖 `host.docker.internal`**。Docker Desktop 默认支持，Linux 上要手动加 `--add-host=host.docker.internal:host-gateway`，文档里给了方案但没做成自动适配。
- **ARP 靶场的网段硬编码**。`172.28.0.0/24` 写死在脚本和文档里，遇到冲突只能改文件或清网络。
- **没有 CI**。理想情况是 push 之后自动起一遍、跑六个 poc、验证 flag 都对。现在是我手动跑。
- **Windows 只验证过 Git Bash 路径**。`lab.sh` 用的是 bash，PowerShell 下只能用原生 `docker compose`，代价是少了自动灌数据那一步。

---

## 写在最后

七个靶场单独看都不难，难的是让它们**在别人的机器上也能跑起来**。

这次做下来最大的收获不是又学会了几个漏洞，而是意识到"能在自己电脑上跑"和"能交付"之间隔着一堆琐碎的事：权限、时序、网段、容器名、路径、编码、布局模型。这些问题单独看都不高级，但它们决定了别人打开浏览器看到的是一个能用的靶场，还是一堆报错。

如果你也在攒自己的靶场，建议早点做合并这件事。越晚越麻烦——我这次合并时，光是让源码里那些写死的 hostname 不用改，就花了不少时间想方案。

---

*仓库地址和博客在导航页页脚。发现的非预期解法欢迎开 issue，附复现步骤。*
