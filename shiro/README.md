# Shiro 多版本靶场

六个 Shiro 版本，三类漏洞，一个镜像。

```
550    1.2.4   硬编码 AES 密钥 → rememberMe 反序列化 RCE
721    1.2.5   密钥随机了，但 CBC 只加密不认证 → padding oracle 伪造身份
绕过   1.4.2 / 1.5.2 / 1.6.0 / 1.7.1   四个路径 CVE，越往后拦得越死
```

前两个是"同一个功能被两种方式打穿"，后四个是"同一个洞被补了四次"。  
放一起是因为：**只看 550 会以为 Shiro 的问题只是密钥写死，看完 721 才知道  
根因是 rememberMe 这条链路从头到尾没有任何完整性校验。**

---

## 起

```bash
./setup.sh
# 或者
docker compose up -d --build
```

首次构建要在容器里跑六次 Maven 打包，5~8 分钟（`settings.xml` 已配阿里云  
镜像）；之后只改 Java 源码时前几层走缓存，约 2 分钟。

| 端口   | 版本          | 内容                                |
| ---- | ----------- | --------------------------------- |
| 8901 | Shiro 1.2.4 | CVE-2016-4437 默认密钥                |
| 8902 | Shiro 1.2.5 | CVE-2019-12422 padding oracle     |
| 8903 | Shiro 1.4.2 | **能打通**：`/;/admin`（本环境下唯一一个）      |
| 8904 | Shiro 1.5.2 | 全挡，一律 302                         |
| 8905 | Shiro 1.6.0 | 分号类直接 400（`InvalidRequestFilter`） |
| 8906 | Shiro 1.7.1 | 同上                                |

想拿 flag 就盯 `8903`；另外三个端口的作用是**对照**——看同一个 payload  
在版本推进中怎么从 302 变成 400、从绕过变成拦死。

账号：`root / root123`、`guest / guest123`。

三个验证脚本都在 `poc/`，零第三方依赖：

```bash
python3 poc/shiro550_exp.py      # 爆破默认 key + CC6 命令执行
python3 poc/shiro721_exp.py      # padding oracle 伪造 root 身份
python3 poc/bypass_exp.py        # 四个版本的绕过矩阵对照
```

四个脚本（含 `poc/aes.py`）的逐行讲解在 [`POC.md`](POC.md)——
函数怎么拆、每个变量为什么是那个值、padding oracle 那两个最容易想错的点。

---

## Shiro-550：密钥写死

### 它到底哪里错了

`AbstractRememberMeManager` 里有一行常量：

```java
public static final byte[] DEFAULT_CIPHER_KEY_BYTES =
        Base64.decode("kPH+bIxk5D2deZiIxcaaaA==");
```

登录时勾选"记住我"，Shiro 会：

1. 把 `PrincipalCollection` 用 Java 序列化
2. 用这个常量当 AES-128 密钥，CBC 模式、PKCS5 填充，加密
3. Base64 后写进 `rememberMe` cookie

下次请求带着 cookie 来，反向走一遍：Base64 解码 → AES 解密 → **`readObject()`**。

第三步是致命的。`readObject` 不校验内容来源、不限制类、也不验证密文  
是不是被人改过。只要密钥能对上，里面是什么就反序列化什么。

密钥是常量 → 全世界都知道 → 攻击者自己加密一段恶意序列化数据 → 命令执行。

### 为什么用 CC6 而不是 CC1

CC1 依赖 `AnnotationInvocationHandler.readObject()`，JDK 8u71 之后那个方法  
不再调用 `setValue()`，链子就断了。CC6 换了入口——`HashMap` 反序列化时  
要算 key 的 `hashCode()`，顺着 `TiedMapEntry` → `LazyMap` → `ChainedTransformer`  
走到 `Runtime.exec`，不碰那个类，8u71+ 依然有效。

靶场容器是 JDK 8，classpath 里显式放了 `commons-collections:3.1`。  
这是刻意的：Shiro 自己不带 gadget，真实世界里能打通是因为业务方引了  
commons-collections。没有这个依赖，反序列化成功也只是抛一堆  
`ClassNotFoundException`。

### 命令没有回显怎么办

`Runtime.exec` 的返回值拿不到。payload 里写的是：

```sh
cat /flag > /tmp/out/flag.txt
```

容器把 `/tmp/out` 映射成 `/out/**` 静态资源，再 HTTP 取回来就行。  
这就是实战里的"落文件 / 带外"，只不过这里换成了本地 HTTP。

### 复现

```bash
python3 poc/shiro550_exp.py
```

脚本会先发一个随便的 cookie，看服务端回不回 `rememberMe=deleteMe`  
（Shiro 的指纹），然后拿 `poc/keys.txt` 里的 19 个常见密钥逐个试。

加密是真的在 Python 里算的：`poc/aes.py` 是自己写的 AES-128-CBC，  
不带任何第三方库，开头有 FIPS-197 和 NIST SP 800-38A 两组官方测试向量自检。  
想换命令、换 key、看不同 key 长度的效果，直接改脚本即可。

期望输出：

```
[+] 指纹命中：服务端回了 rememberMe=deleteMe，确认是 Shiro
[*] CC6 payload: 1223 字节（命令：cat /flag > /tmp/out/flag.txt）
    [6/19] kPH+bIxk5D2deZiIxcaaaA==     … 9 ms  ← 命中
[+] flag：FLAG{shiro550_default_key_rememberme_4b71}
```

命中在第 6 个——因为字典是按"常见程度"排的，不是按答案排的。

### 1.2.5 怎么修的

不是加校验，是**把密钥换成随机的**：`AbstractRememberMeManager` 构造时  
`generateNewKey()` 生成 128 位随机密钥。密钥猜不到了，550 就废了。

但加密方式一点没变——AES-CBC，只加密不认证。这就留下了 721。

---

## Shiro-721：padding oracle

### 为什么换了密钥还能打

CBC 解密的性质：改密文第 i 块，只有第 i 块和第 i+1 块的明文会变，  
后面的块不受影响。而服务端解密后必须校验 PKCS#5 填充——**填充对不对，  
服务端的反应不一样**。

这个"不一样"就是 oracle。攻击者不需要密钥，只要反复改密文、  
问服务端"填充对吗"，就能一个字节一个字节地把中间值 `D(Ci)` 推出来。

### 最容易想错的一步

知道了 `D(Ci)` 之后，直觉上会想直接拼新密文：

```
新 Ci = D(Ci+1) xor 目标明文第 i+1 块
```

**这是错的。** 拼出来的 `Ci` 是**新块**，服务端解密它时用的是新块自己的  
中间值，而那个值从没算过。拿原块的 D 去套新块，解出来是乱码——  
我第一次就是这么写的，`/admin` 一路 302。

正确做法是**逐块倒着造，每造一块就爆破一次它的中间值**：

```
cur = 随机块（先当"最后一块"）
for i = 最后一块 .. 第一块:
    D    = 爆破 D(cur)        ← 每块都要单独爆破，没有捷径
    prev = D xor 明文块[i]     ← 前一块，作为 cur 的 IV
    chain = [cur] + chain
    cur  = prev
最终密文 = cur(IV) + chain
```

代价是 `k 块 × 16 字节 × 256 请求`。payload 越大越慢——这也解释了为什么  
真实 721 利用经常要跑几十分钟，实战里其实不太划算。这个靶场的 payload  
362 字节、23 块，串行跑 51 秒。

### 这个靶场怎么设计 oracle

真实的 Shiro 里，"填充错"和"填充对但反序列化失败"都会走到同一个  
`onRememberedPrincipalFailure`，客户端看不出区别。实战中攻击者靠  
状态码、响应长度、耗时去猜，这也是 721 经常"跑得很玄学"的原因。

为了让复现稳定，这里在应用层把结果暴露出来：

```
GET /__oracle   带 rememberMe cookie
  204  填充合法（解密成功）
  400  填充非法
  404  这个端口没开 721 模式
```

`/__oracle` 的 controller 读的是 `LabState`（ThreadLocal），而 Shiro 的  
过滤器在 servlet 之前就已经跑完了，所以这里能拿到结论。

### 复现

```bash
python3 poc/shiro721_exp.py
```

流程：

1. `guest/guest123` 登录并勾选"记住我"，拿一个**真正合法**的 cookie  
   （这是这个洞的现实前提：你得先能登录一次）
2. 自检：把最后一块的明文做成纯 `0x10` 填充，确认服务端接受
3. 下载 `/payloads/principal_root.bin`（root 的 PrincipalCollection 序列化字节）
4. 从 payload 的最后一块往前，逐块爆破中间值、拼出密文
5. 拿伪造的 cookie 访问 `/admin`

期望输出：

```
[+] 登录成功，rememberMe cookie 416 字节 = IV + 25 块密文
[+] oracle 可用（自检：伪造出合法的 16 字节填充，服务端接受了）
[*] 目标明文：362 字节（SimplePrincipalCollection("root")），要造 23 块密文
    正在造第 23/23 块密文   已用 51.1s
[+] 密文构造完成，用时 51.1 秒（384 字节）
[+] flag：FLAG{shiro721_padding_oracle_root_9c2e}
```

### 为什么 payload 可以比原 cookie 短

362 字节的 payload 补完 PKCS#7 是 368 字节（23 块），比原明文 400 字节短。  
没影响：生成密文时块数是按 **payload** 算的，不是按原 cookie 算的。  
原 cookie 在这里唯一的用途是"证明你能登录"，它的密文块一块都没用到。

这也是 721 比 550 难写的地方——不是为了"改几个字节"，而是  
**在没有密钥的前提下从零造一条合法密文**。

### 1.4.2 怎么修的

不再吐异常细节了，同时对解密后的数据做了更严格的处理。真正的治本  
（给 rememberMe 加 MAC / 换掉自研序列化）一直拖到很后面。

---

## 路径绕过：四个 CVE 的时间线

四个洞的根因是同一个：**Shiro 用 `AntPathMatcher` 判断"这个 URL 要不要鉴权"，  
Spring 用另一套规则判断"这个 URL 交给哪个 controller"。两套规则对同一个  
畸形路径的理解不一致，就会出现"Shiro 认为不用鉴权，Spring 认为就是 /admin"。**

| CVE            | 影响版本    | 修复    | payload 思路        |
| -------------- | ------- | ----- | ----------------- |
| CVE-2020-1957  | < 1.5.2 | 1.5.2 | `/xxx/..;/admin`  |
| CVE-2020-11989 | < 1.5.3 | 1.5.3 | `/;/admin`        |
| CVE-2020-13933 | < 1.6.0 | 1.6.0 | 编码分号 `/admin/%3b` |
| CVE-2020-17523 | < 1.7.1 | 1.7.1 | 尾部空格 `/admin/%20` |

1.6.0 之后还加了一个 `InvalidRequestFilter`，直接对含分号、反斜杠、  
非 ASCII 的 URL 返回 400——很多变体在到达鉴权逻辑之前就被它拍死了。

### 跑矩阵

```bash
python3 poc/bypass_exp.py
```

脚本对四个端口跑同一批 payload，输出一张表：

- `BYPASS` = 200 且页面里有 flag，真的进去了
- `302` = 被 `authc` 拦住，跳登录页
- `400` = 被 `InvalidRequestFilter` 直接拒
- `404` = Shiro 放行了，但 Spring 没路由到 controller

**看这张表比背 CVE 编号有用**：同一个 payload 在四个版本上的四种反应，  
正好把"哪一层在拦"暴露出来。404 尤其说明问题——鉴权已经绕过了，  
只是没打到目标页面，这在实战里换一个路由就能利用。

### 实测结果

这是本仓库镜像上跑出来的（不是"理论上应该"的表）：

| payload          | CVE   | 1.4.2      | 1.5.2 | 1.6.0 | 1.7.1 |
| ---------------- | ----- | ---------- | ----- | ----- | ----- |
| `/admin`（基线）     | —     | 302        | 302   | 302   | 302   |
| `/;/admin`       | 11989 | **BYPASS** | 302   | 400   | 400   |
| `/xxx/..;/admin` | 1957  | 404        | 302   | 400   | 400   |
| `/admin/%3b`     | 13933 | 302        | 302   | 400   | 400   |
| `/admin/%20`     | 17523 | 302        | 302   | 302   | 302   |

几个和"CVE 公告文本"对不上的地方，值得单独记一笔：

- **只有 `/;/admin` 在 1.4.2 上真打通了**。CVE-2020-1957 的  
  `/xxx/..;/admin` 在 1.4.2 上是 404——鉴权确实绕过了（不是 302），  
  但 Spring 没有把 `..;/` 归一化到 `/admin` 的映射上，所以进不了 controller。
- **1.5.2 比公告看起来更严**。公告说 11989 修在 1.5.3，但 1.5.2 上  
  `/;/admin` 已经是 302。原因是本靶场没有设 `context-path`——  
  11989 的典型场景是 `/{context-path}/;/admin`，没有 context-path 时  
  分号被当成路径参数吃掉，Shiro 依然匹配到 `/admin/**`。
- **`/admin/%20` 四个版本全部 302**。17523 的利用依赖于尾部空格让  
  Shiro 的正则匹配不上、而 Spring 归一化时把空格去掉；本环境的  
  Tomcat 9.0.46 在进入 Spring 之前就把它当成非法字符或原样传给  
  Shiro，没有形成"两边不一致"。这个洞在这套环境里打不通，留着当对照。

### 怎么自己加 payload

改 `poc/bypass_exp.py` 里的 `PAYLOADS` 列表，格式是 `(路径, 说明, CVE)`。  
判定逻辑在 `verdict()`：只有 200 且出现 `FLAG{` 才算完整绕过。

---

## 设计取舍

**为什么钉在 Spring Boot 2.3.12**  
CVE-2020-1957 这批是 2020 年的洞，当时的真实环境就是 Boot 2.2/2.3 +  
Tomcat 9.0.3x。换到 Boot 2.7（Tomcat 9.0.8x）以后，Tomcat 自己会归一化  
一部分畸形路径，绕过现象会被"意外修好"，反而看不出 Shiro 版本之间的差异。

**为什么 `/admin` 用 `user` 而不是 `authc`**  
550/721 的攻击结果都是"我拿着一个伪造的 rememberMe 身份"。`authc` 只认  
`isAuthenticated()`，rememberMe 用户不算，攻击成功了也进不去，演示不出来。

|                                            |   |                           |
| ------------------------------------------ | - | ------------------------- |
| `user` 是 \`isAuthenticated()               |   | isRemembered()\`，才对应真实业务里 |
| "记住我也能访问"的配置。bypass 模式反过来用 `authc`——那里要的就是 |   |                           |
| "未登录一律 302"，好让"路径有没有绕过过滤器"一目了然。            |   |                           |

**为什么一个镜像塞六个 jar**  
550/721/绕过的应用逻辑只有 filter chain 和一处身份判定不同，源码完全共用。  
Dockerfile 里循环 `mvn package -Dshiro.version=$v`，运行时用  
`--lab.mode` + `--server.port` 分工。改一处逻辑，六个版本一起生效。

**为什么 CC6 要显式引 commons-collections**  
见上文。没有 gadget，550 只能验证"反序列化发生了"，验证不了"能执行命令"。

---

## 踩过的坑

**1. padding oracle 只发两块，不能发整条 cookie**

第一版老老实实把整条 cookie 发过去，改 `C(i-1)` 去影响 `P(i)`。结果  
`D[1]` 之外全错，但自检还能过——因为自检正好动的是最后一块。

原因：服务端只校验**最后一块**的填充。改 `C(i-1)` 只影响 `P(i)`，  
最后一块 `P(n)` 的填充压根没被动过，于是不管猜什么值服务端都说"合法"。

正解是把密文截成 `[C(i-1), C(i)]` 两块，让第 i 块变成"最后一块"，  
填充校验才对得准。

**2. `Runtime.exec` 是异步的**

550 爆破时，`http()` 一返回就去查 `/out/flag.txt`，查早了文件还没写完。  
表现是"命中位置比真实 key 靠后一位"——把上一个 key 的成果算到了当前 key 头上。  
加 150ms 等待才准。

**3. oracle 别用响应头**

头要在 filter 里补，而 `/__oracle` 一旦返回 204，容器可能立刻把响应  
commit 掉，头就丢了。并发一高就随机丢，表现为"跑着跑着 oracle 没了"。  
改用状态码（由 controller 写）之后彻底稳定。

**4. 复用原 cookie 的中间值去拼新密文，是错的**

见上文"最容易想错的一步"。这个错误很隐蔽：padding 合法、`/admin` 只是  
返回 302，看不出哪里错了。判据是"新块的中间值必须现算"。

**5. Docker legacy builder 里 `RUN cat > file <<EOF` 不展开**

`DOCKER_BUILDKIT=0` 下 heredoc 不会被 shell 处理，`settings.xml` 会变成  
空文件，Maven 报 `Non-readable settings`。改成 `COPY` 就没事了。

---

## 清理

```bash
docker compose down          # 停容器
docker compose down --rmi local -v   # 连镜像一起删
```
