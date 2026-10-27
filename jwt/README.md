# JWT 靶场

同一个「后台管理系统」被四种方式打穿，每次只改一个实现细节。PHP 8.1 + Apache，跑在 Docker 里。

四关的共同目标：拿出 `role=admin` 的令牌，读走对应的 flag。唯一能登录的账号是 `alice / alice123`（普通用户）。

## 端口与启停

```bash
./setup.sh                  # 构建并启动
docker compose down         # 停止
docker compose logs -f web  # 看 Apache 日志
```

- 地址：<http://127.0.0.1:8898/>
- flag：`flags/l1.flag` ~ `flags/l4.flag`，分别挂到容器里的 `/flag_l1` ~ `/flag_l4`

## 关卡

- **L1 弱密钥** —— 最简单也最现实。HS256 密钥是弱口令，离线爆破后自己签 `role=admin`。
  这一关考的不是 JWT，是「HMAC 密钥强度」。
- **L2 alg:none** —— 服务端从令牌里读 `alg`，客户端说 `none` 就跳过验签。改 header + 清空签名即可。
- **L3 算法混淆** —— RS256 私钥签、公钥验。但 HS256 分支把**公开的公钥文本**当 HMAC 密钥，
  于是人手一把签名密钥。公钥就挂在页面上让人下载。
- **L4 kid 注入** —— `kid` 被直接拼进文件路径。`../../../../dev/null` 读到空文件，空字符串成为合法 HMAC 密钥。
- **safe.php** —— 修复对照。把 L1~L4 造出来的令牌粘进去，会看到它们怎么被逐条挡掉。

## 一键验证

```bash
python3 poc/jwt_exp.py        # 四关全打
python3 poc/jwt_exp.py 1 3    # 只打指定关卡
```

纯标准库（`hmac` + `urllib`），不依赖 requests / pyjwt。L1 的爆破字典内嵌在脚本里，
不装 hashcat 也能跑通。

## 每关的实现要点

**L1**：`const SECRET = 'secret'`。爆破方法是拿每个候选词算一次 HMAC-SHA256，
和令牌签名段做常量时间比较。

**L2**：验签函数先读 `jwt_header($token)['alg']`，等于 `none` 就直接把 payload 当已验签结果返回。
真实世界里这个设计来自早期的 JWT 规范草案，后来被明令禁止，但历史实现残留很多。

**L3**：`const PUB = pub.pem`。分支逻辑：

```php
if ($alg === 'HS256') {
    $ok = hash_equals(sign_hs256($input, $pub), $s);   // 公钥当 HMAC 密钥
} else {
    $ok = openssl_verify($input, b64u_decode($s), $pub, OPENSSL_ALGO_SHA256) === 1;
}
```

`hash_equals` 比的是字符串，`openssl_verify` 返回的是 int —— 两种类型混在一个变量里，
写错比较符就会出前面提到的那个坑（见文末）。

**L4**：`$keyfile = __DIR__ . '/keys/' . $kid;`。容器里 `__DIR__` 是 `/var/www/html`，
所以 `/var/www/html/keys/../../../../dev/null` 规范化后就是 `/dev/null`。
选它是因为：一定存在、一定可读、内容为空，而空字符串恰好是 `hash_hmac` 能接受的密钥。

## 目录

```
jwt/
├── Dockerfile            # 禁掉 keys/ 的 Web 访问 + 打开 display_errors
├── compose.yml           # 镜像、端口、flag 挂载、启动时修权限
├── setup.sh
├── flags/                # 四个 flag
├── src/
│   ├── index.php         # 导航
│   ├── l1~l4.php         # 四关
│   ├── safe.php          # 修复对照
│   ├── pub.pem           # L3 的公钥，故意可下载
│   ├── keys/
│   │   ├── default.key   # L4 的正常密钥
│   │   └── rsa_private.pem
│   ├── inc/jwt.php       # Base64URL + 签名（手搓，不用库）
│   ├── inc/common.php    # 账号、flag 读取、页面骨架
│   └── style.css
└── poc/jwt_exp.py
```

## 造靶场时踩的两个坑

记在这里，因为它们是**真实的**踩坑，不是设计好的关卡：

**1. 私钥 `600` 导致 `openssl_sign` 静默签出空签名。**
宿主机上 `openssl genpkey` 生成的是 `-rw-------`，bind mount 进容器后保留权限位，
Apache 以 `www-data` 运行读不到。`openssl_sign` 失败时不抛异常，`$rawsig` 就是空的，
令牌长得完全正常、只是签名段为空。
现在的处理：`compose.yml` 的 `command` 在拉起 Apache 前先 `chmod 644`，
`l3.php` 里也加了 `openssl_sign` 的返回值检查。
顺带一道真实教训：**密钥放在 web 根目录下本身就不对**，所以 `keys/` 整目录被 Apache 拒掉（403）。

**2. `$ok = openssl_verify(...) === 1` 之后又 `if ($ok !== 1)`。**
`===` 把 int 转成了 bool，`true !== 1` 恒为 true，于是对照页对任何令牌都报「签名校验失败」。
这种 bug 的表现很有迷惑性：攻击确实被挡住了，看着像「防护生效」，其实是逻辑写错。
定位方法是拿同一份令牌分别走 CLI 和 HTTP —— CLI 里 `openssl_verify` 返回 1、HTTP 却报失败，
说明差异在输入或比较，不在密码学。
