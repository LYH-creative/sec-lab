# 反序列化靶场

PHP 与 Java 两条线的本地练习环境，全部跑在 Docker 里，flag 在各自容器的 `/flag`。

## 端口

| 端口 | 容器 | 运行时 | 内容 |
|------|------|--------|------|
| 8890 | deser-php | PHP 8.1 + Apache | L1 魔术方法 / L2 POP 链 / L3 private 属性 |
| 8891 | deser-php74 | PHP 7.4 + Apache | L4 phar（**只有 7.x 能触发**） |
| 8892 | deser-java | JDK 8 + commons-collections 3.1 | Java 原生反序列化 / CC6 |

## 启停

```bash
./setup.sh                       # 首次 clone 后跑这个：建 uploads、给权限、构建并启动
docker compose down              # 停止
docker compose logs -f java      # 看服务端日志
```

`setup.sh` 里那句 `chmod 777 php/src/uploads` 不能省 —— L4 要让容器里的 `www-data` 往这个目录写文件，clone 下来的目录默认是 755。

如果 build 时报 `buildx/activity ... operation not permitted`，说明环境挡住了 buildx，改用经典构建器：

```bash
DOCKER_BUILDKIT=0 docker compose up -d --build
```

Java 镜像在 build 阶段会从 Maven Central 下载 `commons-collections-3.1.jar`，所以第一次构建需要联网。

## 练习入口

- 浏览器打开 http://127.0.0.1:8890/ —— L1~L3 的导航页
- L4 直接访问 http://127.0.0.1:8891/l4.php
- Java 是纯接口，没有页面：
  - `POST /api/import`，请求体就是裸的序列化字节流
  - `GET /static/<file>` 读 `/tmp/out/` 下的文件（命令执行的结果落地处）

## 一键验证（答案，先自己做再看）

```bash
python3 poc/php_exp.py all      # L1~L4，四关
python3 poc/java_exp.py         # Java CC6
```

两个脚本都是纯标准库，不依赖 requests。

## 目录

```
deserialization/
├── compose.yml
├── setup.sh                    # 一键起靶场
├── php/
│   ├── Dockerfile              # 用 ARG 参数化版本与 flag，两个容器共用
│   ├── src/
│   │   ├── index.php           # L1~L3 导航
│   │   ├── l1.php … l4.php     # 四关入口
│   │   ├── inc/classes.php     # 全部业务类（魔术方法都在这）
│   │   └── uploads/            # L4 上传目录，需要 777
│   └── poc/gen_phar.php        # 生成恶意 phar（容器内执行）
├── java/
│   ├── Dockerfile              # build 时下载 commons-collections 3.1
│   ├── server/DeserServer.java # HTTP + ObjectInputStream
│   └── poc/Cc6Gen.java         # 手写 CC6 链，输出 base64
└── poc/
    ├── php_exp.py
    └── java_exp.py
```

## 实测结论（这些是踩过的坑，不是抄的）

PHP 8.1.34 上验证过，**网上很多老 payload 已经失效**：

- 属性数写大绕过 `__wakeup`（CVE-2016-7124）：`O:4:"Gate":99:{...}` → `unserialize()` 直接返回 `false`，对象都不创建
- 属性数写小：`__wakeup` 照常执行，重置生效
- `C:` 格式：类没实现 `Serializable` 时属性全丢，拿不到可控对象
- 让 `__wakeup` 内部抛异常：对象会被 PHP 丢弃，**`__destruct` 根本不执行**，白忙
- `private` 属性在序列化串里是 `\0类名\0属性名`，长度按**字节**算（`\0Gate\0cmd` 是 9 字节）

phar 的版本差异（重要）：

- PHP 7.4：`file_exists` / `is_file` / `file_get_contents` / `md5_file` / `stat` / `filesize` 等文件函数碰到 `phar://` 就会反序列化 metadata
- PHP 8.1：上面这些**全部不再触发**（元数据改成惰性反序列化），只有显式 `new Phar()->getMetadata()` 才会
- 所以 L4 单独跑在 7.4 上；打 8.x 的站要重新找触发点

Java：

- CC1（TransformedMap + AnnotationInvocationHandler）在 JDK 8u71+ 已失效
- CC6 从 `HashMap.readObject → hashCode` 入口进，不碰那个类，8u71+ 依然有效
- 构造 payload 时必须先用假的 `ChainedTransformer`，否则 `map.put()` 的那一刻命令就在本地执行了；并且要 `lazyMap.remove(key)`，不然反序列化时命中缓存，链子不会触发
