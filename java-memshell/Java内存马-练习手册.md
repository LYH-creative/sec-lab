# Java 内存马练习手册

配套靶场：`~/代码库/靶场/java-memshell/`（独立容器，不并入根编排）

---

## 写在前面

本仓库其他靶场练的是**漏洞**：XXE 的解析开关、JWT 的算法混淆、Shiro 的硬编码密钥、
Log4Shell 的 `${jndi:}`，都能打开源码指着某一行说"洞在这"。

Java 内存马不属于这一类。**它不是漏洞，是拿到任意代码执行（RCE）之后的一种驻留方式**。
业务代码一行没错，依赖清单也没有 CVE；整个过程用的是 Servlet 规范和容器提供的合法 API，
只不过用在了容器不希望的时间点。

这份手册要做完四件事：

- 把「运行时动态注册」和「无文件加载字节码」这两件事拆开，看清各自解决什么问题
- 六关递进：基线 → 标准 API 被拒 → 注入 → 命中/放行 → 磁盘查不到但堆里查得到 → 重启消失
- 打掉几个很常见的错误结论（第 9 节，附错误结论原文与实测反证）
- 收尾到检测与防御：为什么文件扫描必然失效，以及该从哪里查

**前置**：能看懂简单 Java、知道 HTTP 请求头是什么、知道 Servlet Filter 是"请求到达 Servlet
之前的一层拦截"即可。不需要读过 Spring 或 Tomcat 源码。

**边界与约定**：全部在本机自建靶场里做，端口只绑 `127.0.0.1`。教学版 Filter **只做无害回显，
不含命令执行、不做免杀、不做持久化** —— 注入与驻留的机制是完整的，替换掉回显逻辑就是
真实武器，但本靶场不实现那一部分。对未授权目标做注入是攻击行为。

一份文档、一条命令链，全部在本机实测过（macOS arm64 / Docker 29.7.2 /
`eclipse-temurin:8-jdk` 1.8.0_504 / Tomcat 9.0.46 / Spring Boot 2.3.12.RELEASE /
宿主 `javac 17.0.19` / Python 3.12.13，2026-11-17）。
**标注「源码」的地方是读源码或 `javap` 得出的，标注「实测」的地方是跑出来的**，两者不混。

---

## 0. 三分钟把环境跑起来

```bash
cd ~/代码库/靶场
./java-memshell/up.sh
```

`up.sh` 做四件事：从已有的 `sec-lab/shiro:1.0` 镜像里解出 Spring Boot / Tomcat 依赖
（不联网、不用 Maven）→ 用 `--release 8` 编译两份代码 → 以**只读挂载**起一个全新容器
→ 轮询等就绪。每次执行都会删掉旧容器，所以永远拿到「未注入」的干净状态。

实测输出：

```
[*] 编译目标侧应用（--release 8，宿主 javac 17 编出的 class 必须降到 52）...
[*] 启动目标容器 ...
[+] 就绪（6s）：http://127.0.0.1:19090/
    目标侧：JDK 8 + Tomcat 9.0.46 + Spring Boot 2.3.12，/app 只读
    攻击者侧：attacker/evil/EvilFilter.class（不挂载进容器）
```

两侧分得非常干净，这是整份手册最需要记住的划分：

- **攻击者侧（宿主机）**：`src/evil/EvilFilter.java` 编译成
  `attacker/evil/EvilFilter.class`（2036 字节），再转成 base64 通过 HTTP 发出去。
  `attacker/`、`src/` 都**不挂载进容器**
- **目标侧（容器）**：只有 `classes/`（靶场应用）、`libs/`（37 个 jar）、`start.sh`，
  三者全部 `:ro`。容器里从来不存在 `EvilFilter.class` 这个文件

确认容器起来（实测 `docker logs memshell-lab` 节选）：

```
Starting Servlet engine: [Apache Tomcat/9.0.46]
Tomcat started on port(s): 8080 (http) with context path ''
Started MemShellLab in 0.957 seconds (JVM running for 1.302)
```

一键演练 L0~L4：

```bash
python3 java-memshell/poc/run.py
```

脚本只用 Python 标准库（`urllib` / `base64`），会把每一关的真实响应打印出来，
第 3~8 节的输出就来自它。跑完想重来，再执行一次 `up.sh` 即可。

**停**：

```bash
./java-memshell/down.sh
```

> `19090` 上的 `/__lab/inject` 是一个**真的能往 JVM 里注册 Filter** 的端点。
> 只绑 `127.0.0.1`，别改成 `0.0.0.0`，别放进有多人使用的网络。
> 本靶场不并入根 `docker-compose.yml`，避免和 8880~8906 那批端口、以及各靶场的独立网络纠缠。

---

## 1. 原理：五句话钉死

### 1.1 请求链是堆里的对象，不是配置文件里的文本

Tomcat 一次请求大致走 `Connector → Engine → Host → Context → Wrapper`，中途经过
`ApplicationFilterChain`。谁在这个链里、按什么顺序执行，由 `StandardContext` 里几个
字段决定。用 `javap -p` 看本靶场实际用的 `tomcat-embed-core-9.0.46.jar`（**源码**）：

```
private java.util.Map<String, FilterDef> filterDefs;
private java.util.Map<String, ApplicationFilterConfig> filterConfigs;
public  void addFilterDef(FilterDef);
public  void addFilterMapBefore(FilterMap);
public  FilterDef[] findFilterDefs();
public  FilterMap[] findFilterMaps();
public  boolean filterStart();
```

`filterMaps` 的实际类型是内部类 `StandardContext$ContextFilterMaps`，里面是
`private FilterMap[] array` 加 `private int insertPoint`（**源码**，后文 9.① 会用到）。

这些都是 JVM 堆上的 `Map` 和数组。改它们 = 改请求处理逻辑，跟 `web.xml`、
磁盘上的 jar、配置文件**没有任何关系**。

一次请求真的会按这个数组走。第 9 节 ② 里那次 500 抛出的调用栈（**实测**，自内向外读）：

```
ApplicationFilterChain.internalDoFilter
  WsFilter.doFilter
  RequestContextFilter.doFilterInternal
  FormContentFilter.doFilterInternal
  CharacterEncodingFilter.doFilterInternal
  StandardWrapperValve.invoke → dispatcherServlet
```

从外到内的执行顺序，和 L0 里 `filterMaps` 数组的顺序完全一致。

### 1.2 动态注册是合法功能，但只在启动阶段开放

Servlet 3.0 起有 `ServletContext.addFilter()` / `addServlet()`，本来是给框架用的 ——
Spring Boot 注册 `DispatcherServlet`、`characterEncodingFilter` 就靠它，L0 基线里那 4 个
Filter 全是这么来的。

但 Tomcat 的 `ApplicationContext` 加了一道生命周期校验。反编译私有
`addFilter(String, String, Filter)`（**源码**）：

```
41: StandardContext.getState()
44: LifecycleState.STARTING_PREP
47: LifecycleState.equals(...)
50: ifne 80                       // 相等才继续
53: new IllegalStateException     // 否则抛异常
```

也就是说：**只有 `STARTING_PREP` 阶段能动态注册，应用启动完成之后一律拒绝**。
L1 实测到的原文是：

```
Filters cannot be added to context [] as the context has been initialised
```

所以运行时想注册，只能反射绕过这层校验，直接改 `StandardContext` 的 `filterDefs` /
`filterMaps`。**这是内存马全部技术含量所在** —— 不是绕过了什么安全机制，是绕过了
一个生命周期检查。

### 1.3 「无文件」来自 `defineClass`，不是来自"删文件删得干净"

`ClassLoader.defineClass(String, byte[], int, int)` 直接从字节数组定义类：
不读磁盘、不进任何 jar、不产生 `.class` 文件。这样定义出来的类
`getProtectionDomain().getCodeSource()` 返回 `null`（L2 实测）：

```
injected: evil.EvilFilter codeSource=(null <no signer certificates>)
```

对照组是 L0 基线里的 4 个正常 Filter，它们的 `codeSource` 全是
`file:/app/libs/spring-boot-2.3.12.RELEASE.jar` 之类。

所以"先落地一个 JSP、注入完再删掉"只是**一种**做法，而且不是最干净的。
真正的无文件是：**字节码从网络/内存来，自始至终没碰过文件系统**。

### 1.4 为什么 Filter 是最常用的落点

- 在 Servlet 路由**之前**执行。L3 实测连 `/any/path` 这种本来会 404 的路径都被截获
- `/*` 通配，不新增 URL，访问日志里只有正常业务路径
- 可以「命中特征才处理，其余 `chain.doFilter()` 放行」，业务完全无感（L3 实测）
- 位置可选，能插到鉴权 Filter 之前

其他形态按检测难度从低到高：Servlet 型（多一个陌生 URL，最容易被基线发现）、
Listener 型（`ServletRequestListener`，连 URL 都不需要）、Valve 型（插 Tomcat Pipeline，
比 Filter 更底层）、Spring 型（`RequestMappingHandlerMapping.registerMapping()`）、
Agent 型（`Instrumentation` + `retransformClasses` 改已有类字节码，不新增任何组件，最难查）。

### 1.5 代价：重启即消失

JVM 一停，堆清空，马和它的类一起没（L5 实测）。这既是内存马的短板，
也决定了应急响应顺序：**先 dump 堆、留证据，再重启**，别一上来就重启把现场冲掉。

### 1.6 整条链

```
攻击者侧：EvilFilter.class → base64（本靶场）
          真实场景：反序列化流 / JNDI / SpEL / 上传的 JSP / Agent attach
        │
        ▼  已经拿到任意代码执行（本靶场用 /__lab/inject 模拟）
反射 ServletContext → ApplicationContext → StandardContext
        │
        ▼  defineClass(byte[])       ← 类只在堆里，CodeSource = null
改注册表：addFilterDef → addFilterMapBefore → filterStart
        │
        ▼
之后每个 HTTP 请求都先经过这个 Filter
        │
        ├─ 命中特征头 → 执行注入的逻辑
        └─ 否则 chain.doFilter() 放行，业务无感
        │
        ▼
重启 JVM → 全部消失
```

**一句话**：内存马 = 滥用容器合法的动态注册能力 + `defineClass` 无文件加载，
把恶意逻辑塞进请求处理链；它绕开的是「查文件」，绕不开「查内存」。

---

## 2. 靶场这一页怎么读

### 2.1 目标侧：`src/lab/MemShellLab.java`

五个端点（**源码**）：

- `GET /` —— 正常业务页，返回 `business-ok`，用来证明"马在不在业务都照常"
- `GET /__lab/scan` —— **判题器**：把 JVM 里真实的 `filterDefs` / `filterMaps` 全列出来，
  每个 Filter 打印类名、`codeSource`、类加载器
- `GET /__lab/inject?b64=...` —— 模拟 RCE 入口：收一段 base64 字节码，调注入器
- `GET /__lab/standard` —— 对照组：走标准 `ServletContext.addFilter()`，看它被拒绝
- `GET /__lab/probe` —— 自查应用 classpath 里有没有 `evil.EvilFilter`

`/__lab/*` 是**靶场特有的教学装置**。真实环境里没有这些端点，注入通道是反序列化、
JNDI、表达式注入之类；把通道抽象成一个 HTTP 参数，是为了能一条 `curl` 演示，
也能把「入口」和「马本体」彻底拆开看。

### 2.2 注入器：`src/lab/MemShellInject.java`

三个动作：

- `context(ServletContext)` —— 顺着 `context` 字段一层层往里走，直到
  `instanceof StandardContext`。写成循环而不是写死两层，是因为不同容器/版本起始对象不同；
  本靶场实测拿到的是 `org.springframework.boot.web.embedded.tomcat.TomcatEmbeddedContext`
  （`StandardContext` 的子类），用 `instanceof` 才匹配得上
- `defineClass` —— 用 `Thread.currentThread().getContextClassLoader()`。Web 请求线程里
  它是 `TomcatEmbeddedWebappClassLoader`（L3 实测），能解析 `javax.servlet.*`
- `addFilterDef` → `addFilterMapBefore` → `filterStart()` —— 定义、映射、重建
  `filterConfigs` 让新 Filter 立刻生效

### 2.3 马本体：`src/evil/EvilFilter.java`

包名故意叫 `evil`，和目标应用不同包，**单独编译，不进 `classes/`**。
`doFilter` 里只有一段无害回显：打印 `mem-shell alive`、JVM 进程名、类名、加载器、
`codeSource`。带 `X-Lab-Probe` 请求头才响应，否则原样放行。

### 2.4 为什么走 GET 参数

2036 字节的 class 转成 base64 是 2716 字符，一条 `curl -G --data-urlencode` 就能发
（L2 实测 HTTP 200）。真实利用里字节通常来自请求体或反序列化流，走 GET 只是为了
手册里的命令能复制粘贴。

---

## 3. L0 · 基线：先看干净的注册表长什么样

**目标**：记住"正常"是什么样，后面所有"多出来的东西"都以它为参照。

```bash
curl -s http://127.0.0.1:19090/__lab/scan
```

实测输出（完整）：

```
jvm=1.8.0_504  process=1@a105170e4e9f
context=org.springframework.boot.web.embedded.tomcat.TomcatEmbeddedContext
evilClassOnClasspath=false
filterDefs=4
  [requestContextFilter]
    class=org.springframework.boot.web.servlet.filter.OrderedRequestContextFilter
    codeSource=(file:/app/libs/spring-boot-2.3.12.RELEASE.jar <no signer certificates>)
    loader=sun.misc.Launcher$AppClassLoader
  [Tomcat WebSocket (JSR356) Filter]
    class=org.apache.tomcat.websocket.server.WsFilter
    codeSource=(file:/app/libs/tomcat-embed-websocket-9.0.46.jar <no signer certificates>)
    loader=sun.misc.Launcher$AppClassLoader
  [characterEncodingFilter]
    class=org.springframework.boot.web.servlet.filter.OrderedCharacterEncodingFilter
    codeSource=(file:/app/libs/spring-boot-2.3.12.RELEASE.jar <no signer certificates>)
    loader=sun.misc.Launcher$AppClassLoader
  [formContentFilter]
    class=org.springframework.boot.web.servlet.filter.OrderedFormContentFilter
    codeSource=(file:/app/libs/spring-boot-2.3.12.RELEASE.jar <no signer certificates>)
    loader=sun.misc.Launcher$AppClassLoader
filterMaps=4
  characterEncodingFilter -> [/*]
  formContentFilter -> [/*]
  requestContextFilter -> [/*]
  Tomcat WebSocket (JSR356) Filter -> [/*]
```

四个要点（`process=1@...` 里的容器 ID 每次 `up.sh` 重建都会变，其余行固定）：

- `filterDefs=4`、`filterMaps=4`，一一对应
- 4 个 Filter 的 `codeSource` **全部指向 `/app/libs/*.jar`**，没有一个为 `null`
- `evilClassOnClasspath=false`，JVM 里还没有这个类
- `filterMaps` 的顺序就是请求经过 Filter 的顺序（1.1 的调用栈已佐证）

---

## 4. L1 · 标准 API 被拒：为什么必须反射

**目标**：亲手看到那道生命周期闸门，而不是听别人说"标准 API 不行"。

```bash
curl -s http://127.0.0.1:19090/__lab/standard
```

实测输出：

```
standard API rejected
  java.lang.IllegalStateException
  Filters cannot be added to context [] as the context has been initialised
```

`poc/run.py` 的 L1 段把它打印成：

```
── L1 · 标准 API 对照 ────────────────────────────────
  standard API rejected
    java.lang.IllegalStateException
    Filters cannot be added to context [] as the context has been initialised
```

配合 1.2 节反编译出来的 `getState() != STARTING_PREP → IllegalStateException`（**源码**），
结论很直接：

> Servlet 3.0 的动态注册是**启动期**功能。应用跑起来之后，正规门被关上了；
> 内存马走的是反射直改 `StandardContext` 的后门，压根不经过 `ApplicationContext` 的校验。

这一关也解释了为什么防守方不能只盯着"有没有调用 `addFilter`"。
真正该盯的是 `StandardContext.addFilterDef` / `addFilterMapBefore` 这类内部方法。

---

## 5. L2 · 注入：把字节码送进目标 JVM

**目标**：完成一次注入，并确认新类的 `codeSource` 是 `null`。

手工来一遍：

```bash
cd ~/代码库/靶场/java-memshell
B64=$(base64 -i attacker/evil/EvilFilter.class | tr -d '\n')
curl -s -G "http://127.0.0.1:19090/__lab/inject" --data-urlencode "b64=$B64"
```

实测输出：

```
injected: evil.EvilFilter codeSource=(null <no signer certificates>)
```

`poc/run.py` 的 L2 段（实测）：

```
── L2 · 注入 ───────────────────────────────────
  攻击者侧：EvilFilter.class 2036 bytes → base64 2716 chars
  HTTP 200  injected: evil.EvilFilter codeSource=(null <no signer certificates>)
```

逐字读这行返回值：

- `evil.EvilFilter` —— 类名从字节码里读出来的，注入器没有写死类名
- `codeSource=(null ...)` —— 这个类**没有磁盘来源**。它不是从某个 jar 加载的，
  是 `defineClass` 从 `byte[]` 直接定义的

再打一次 `scan`，`filterDefs` 从 4 变成 5，多出来的是（实测）：

```
  [lab-probe-filter]
    class=evil.EvilFilter
    codeSource=(null <no signer certificates>)
    loader=org.springframework.boot.web.embedded.tomcat.TomcatEmbeddedWebappClassLoader
```

**这一关的结论**：注入不需要写文件、不需要重启、不需要改配置，一次 HTTP 请求，
目标进程里的请求链就变了。

---

## 6. L3 · 命中与放行：为什么平时看不出异常

**目标**：验证「选择性响应」这个行为，理解为什么业务监控和访问日志都发现不了。

```bash
curl -s -H "X-Lab-Probe: 1" http://127.0.0.1:19090/
curl -s                      http://127.0.0.1:19090/
curl -s -H "X-Lab-Probe: 1" http://127.0.0.1:19090/any/path
```

实测输出：

```
===== 带 X-Lab-Probe =====
mem-shell alive
jvm=1@a105170e4e9f
class=evil.EvilFilter
loader=org.springframework.boot.web.embedded.tomcat.TomcatEmbeddedWebappClassLoader
codeSource=(null <no signer certificates>)

===== 不带请求头 =====
business-ok
app=memshell-lab
path=/

===== 带请求头打不存在的路径 =====
mem-shell alive
jvm=1@a105170e4e9f
class=evil.EvilFilter
loader=org.springframework.boot.web.embedded.tomcat.TomcatEmbeddedWebappClassLoader
codeSource=(null <no signer certificates>)
```

`poc/run.py` 的 L3 段（实测）：

```
── L3 · 命中与放行 ────────────────────────────
  GET / + X-Lab-Probe     → HTTP 200  mem-shell alive
    jvm=1@a105170e4e9f
    class=evil.EvilFilter
    loader=org.springframework.boot.web.embedded.tomcat.TomcatEmbeddedWebappClassLoader
    codeSource=(null <no signer certificates>)
  GET / 无请求头          → HTTP 200  business-ok
  GET /any/path + 请求头  → HTTP 200  mem-shell alive
```

三条结论：

- **业务无感**：不带特征头就是原来的 `business-ok`，状态码 200，页面没变化
- **早于路由**：`/any/path` 本来该 404，却被 Filter 截获返回 200。
  Filter 在 `DispatcherServlet` 之前执行，所以"路径不存在"根本不影响它拿到请求
- **日志只有正常 URL**：不带特征头的请求和平时一模一样；带特征头的请求看起来也只是
  访问了一个普通路径。没有任何新文件、新 URL、异常堆栈

---

## 7. L4 · 磁盘查不到，堆里查得到

**目标**：这是全手册最关键的一关。分别用「文件扫描」和「查 JVM 内存」两种方法查同一个
后门，看结果差多少。

### 7.1 文件扫描：什么都没有

```bash
docker exec memshell-lab sh -c 'find / -iname "*EvilFilter*" 2>/dev/null'
```

实测输出（**空**）：

```
(find 结束，上面无输出即无文件)
```

顺手确认目标侧根本写不了文件：

```bash
docker exec memshell-lab sh -c 'touch /app/classes/.write-test'
```

```
touch: cannot touch '/app/classes/.write-test': Read-only file system
```

也就是说，哪怕把根文件系统做成只读、哪怕上了文件完整性校验、webshell 特征库、
`web.xml` 基线对比，这一关的马**一个都触发不了** ——它压根没有文件。

### 7.2 查 JVM 内存：证据全在

```bash
curl -s http://127.0.0.1:19090/__lab/scan
```

关键行（实测）：

```
evilClassOnClasspath=false
filterDefs=5
  [lab-probe-filter]
    class=evil.EvilFilter
    codeSource=(null <no signer certificates>)
  lab-probe-filter -> [/*]
```

再看 JVM 自己知道什么：

```bash
docker exec memshell-lab sh -c 'jcmd 1 GC.class_histogram | grep -i evilfilter'
```

实测输出：

```
1761:             1             16  evil.EvilFilter
```

`jcmd` 的类直方图里，这个类有 **1 个实例、16 字节**，确确实实活在堆里。

`poc/run.py` 的 L4 段（实测）：

```
── L4 · 运行时检测 ────────────────────────────
  evilClassOnClasspath=false
  filterDefs=5
  filterMaps=5
  新增的 FilterDef：
    [lab-probe-filter]
    class=evil.EvilFilter
    codeSource=(null <no signer certificates>)
    loader=org.springframework.boot.web.embedded.tomcat.TomcatEmbeddedWebappClassLoader
  filterMaps 顺序（注意 lab-probe-filter 并不在数组第 0 位）：
    characterEncodingFilter -> [/*]
    formContentFilter -> [/*]
    requestContextFilter -> [/*]
    lab-probe-filter -> [/*]
    Tomcat WebSocket (JSR356) Filter -> [/*]
```

### 7.3 检测特征怎么提炼

对照 L0 基线，可疑项一目了然：

- `filterDefs` 数量从 4 变 5，多出一个不在基线里的名字
- 它的 `codeSource=null` —— 正常 Filter 都来自某个 jar，这条没有任何磁盘来源
- 类名 `evil.EvilFilter` 不在依赖清单里，也不是 Spring / Tomcat 的类
- `filterMaps` 里多了一条 `/*` 映射

`evilClassOnClasspath=false` 这条要特别解释一下，很容易误读：它不是说"类不在 JVM 里"
（`jcmd` 已经证明在了），而是说 `Class.forName("evil.EvilFilter")` 用的加载器
（`AppClassLoader`）找不到它 —— 这个类定义在 `TomcatEmbeddedWebappClassLoader`
里（L3 的 `loader=` 行）。第 9 节 ③ 专门拆这个坑。

---

## 8. L5 · 重启即消失

**目标**：确认内存马的生命周期边界，并理解应急响应为什么要先取证。

```bash
docker restart memshell-lab
# 等应用起来（约 6s）
curl -s -H "X-Lab-Probe: 1" http://127.0.0.1:19090/
curl -s http://127.0.0.1:19090/__lab/scan | grep -E 'filterDefs=|filterMaps=|lab-probe|evilClassOnClasspath='
docker exec memshell-lab sh -c 'jcmd 1 GC.class_histogram | grep -i evilfilter || echo "(已无 evil.EvilFilter)"'
```

实测输出：

```
就绪（6s）
-- 重启后带 X-Lab-Probe --
business-ok
app=memshell-lab
path=/
-- 重启后 scan --
evilClassOnClasspath=false
filterDefs=4
filterMaps=4
-- 重启后 jcmd --
(已无 evil.EvilFilter)
```

全回去了：请求头不再命中、`filterDefs` 回到 4、类从直方图里消失。

**这一关的结论**：内存马活在**进程**里，不活在磁盘上。重启是最简单有效的清除手段，
但同时也会抹掉全部证据。所以顺序必须是：

1. 先 dump 堆（`jmap -dump` / `jcmd GC.heap_dump`）、导出运行时 Filter 列表
2. 再重启或隔离实例
3. 最后回头找**注入通道**（那个 RCE 入口），否则重启完对方会再打一次

---

## 9. 认知纠错：六个错误结论（含原文与实测反证）

这一节按「当时的结论原文 → 为什么这么想 → 实测打脸 → 正确说法」写。
前四条是本靶场搭建和上一轮讲解中真实出现过的判断，不是编的教学案例。

### ① 「`addFilterMapBefore` 保证插到链首」

- **结论原文**（上一轮讲解里写下的）：*"用 `addFilterMapBefore` 而不是 `addFilterMap`，
  保证插在链首，`filterStart()` 重建 `filterConfigs` 让它立刻生效。"*
- **为什么这么想**：方法名叫 `Before`，直觉上就是"放到最前面"。
- **实测反证**：L4 的 `filterMaps` 顺序是
  `characterEncodingFilter → formContentFilter → requestContextFilter → lab-probe-filter → WsFilter`，
  新映射排在**第 4 位（共 5 个）**，不是 index 0。
- **源码反证**：反编译 `StandardContext$ContextFilterMaps`（**源码**），
  这个类有 `private int insertPoint`；`addBefore()` 的字节码用
  `System.arraycopy(array, 0, results, 0, insertPoint)` 复制前半段、
  `results[insertPoint] = filterMap` 插入新项。它插的是 `insertPoint`，
  **不是 0**。`insertPoint` 由 `add()` 维护，用来隔开 URL 映射和 servlet-name 映射。
- **正确说法**：`addFilterMapBefore` 保证的是"排在 servlet-name 映射之前"，
  不保证绝对链首。本靶场里它已经足够早（在 Servlet 之前，L3 的 `/any/path` 命中
  就是证据），但要真正占住 index 0，得反射改 `ContextFilterMaps.array` 本身。
  真实内存马里确实有人这么做。

### ② 「注入返回 500，肯定是反射拿 `StandardContext` 的写法错了」

- **结论原文**（第一次跑注入时）：*"HTTP 500，说明 `ApplicationContextFacade →
  ApplicationContext → StandardContext` 这条反射链字段名对不上，或者 `defineClass`
  在 JDK 8 上被拦了。"*
- **实测反证**：`docker logs memshell-lab` 的根因是

  ```
  java.lang.IllegalArgumentException: Name for argument of type [java.lang.String]
  not specified, and parameter name information not found in class file either.
  ```

  请求**根本没进注入器**，在 Spring MVC 绑定 `@RequestParam String b64` 时就挂了。
  `javac` 默认不写 `MethodParameters` 属性，Spring 拿不到参数名。
- **正确说法**：显式写 `@RequestParam("b64")`（或者编译时加 `-parameters`）。
  改完重新编译、重启，注入立刻返回
  `injected: evil.EvilFilter codeSource=(null ...)`。
  **排障先看根因，别急着怀疑最"高深"的那段代码。**

### ③ 「类都注入了，`Class.forName` 应该能找到它」

- **结论原文**：*"L4 里 `/__lab/probe` 还显示 `evilClassOnClasspath=false`，
  说明检测端点写错了，或者注入其实没成功。"*
- **实测反证**：同一时刻 L3 带请求头能命中 `mem-shell alive`，
  `jcmd 1 GC.class_histogram` 里有 `1  16  evil.EvilFilter`。类确实在。
  `/__lab/probe` 里 `Class.forName` 由 `lab.MemShellLab` 发起，用的是
  `sun.misc.Launcher$AppClassLoader`；而注入用的是 Web 请求线程的
  `Thread.currentThread().getContextClassLoader()`，L3 实测是
  `org.springframework.boot.web.embedded.tomcat.TomcatEmbeddedWebappClassLoader`。
- **正确说法**：`false` 是对的，它只说明"应用类加载器里没有"。
  类加载器不同，`Class.forName` 找不到很正常。检测要遍历
  `filterDefs` 里每个 Filter **自己的** `getClass()`，或者用 `jcmd` / Arthas
  这种直接看 JVM 全量类的工具，不能只靠一次 `Class.forName`。

### ④ 「宿主 `javac 17` 编译一下就能给 JDK 8 用」

- **结论原文**：*"就是个普通 Java 类，本机有 `javac` 直接编了发过去就行。"*
- **实测反证**：宿主默认编出的 class `major = 61`，拷进容器运行：

  ```
  java.lang.UnsupportedClassVersionError: V has been compiled by a more recent
  version of the Java Runtime (class file version 61.0), this version of the
  Java Runtime only recognizes class file versions up to 52.0
  ```

- **正确说法**：目标 JDK 8 只认 major 52。`up.sh` 里统一用
  `javac --release 8`，编译后校验过 `classes/lab/MemShellLab.class` 和
  `attacker/evil/EvilFilter.class` 都是 **52**。真实攻防里字节码必须按目标
  JDK 版本生成，这条比任何 payload 技巧都先决定成败。

### ⑤ 「只读根文件系统 / 文件查杀能挡住内存马」

- **结论原文**：*"容器 `/app` 挂成 `:ro`，落不了盘就植入不了。"*
- **实测反证**：L4 的 `touch /app/classes/.write-test` 确实报
  `Read-only file system`，但 L2 注入照样 HTTP 200、L3 照样命中。
  全程没有任何写文件动作。
- **正确说法**：只读文件系统挡的是**落地型** webshell，对纯内存注入无效。
  它仍然值得做（能砍掉大部分落地路径），但不能当成内存马的防线。
  防线要放在 RASP / 类加载行为 / 运行时注册表基线上。

### ⑥ 「内存马是一个漏洞，打个补丁就好了」

- **结论原文**（常见入门误解）：*"内存马应该是 Tomcat 的某个 CVE，升级版本就没事。"*
- **实测反证**：本靶场用的是**没有 CVE 的** Spring Boot 2.3.12 + Tomcat 9.0.46，
  业务代码只有几个端点，`addFilter` 是规范里的合法 API，`defineClass` 是 JDK
  的标准方法。L2 依然一次请求就注入成功。
- **正确说法**：内存马是 **RCE 的下游**。要防的是上游那个入口
  （反序列化、JNDI、表达式注入、文件上传），以及运行时对
  `defineClass` + `addFilterDef` 这个组合的监控。打 Tomcat 补丁解决不了它。

### 环境坑（不影响原理，但会浪费时间）

- **重复注入会失败**：同一个 ClassLoader 不能重复定义同名类。实测第二次注入：

  ```
  inject failed: java.lang.reflect.InvocationTargetException
    cause=java.lang.LinkageError: loader (instance of
    .../TomcatEmbeddedWebappClassLoader): attempted duplicate class definition
    for name: "evil/EvilFilter"
  ```

  应用没崩（`HTTP 200`），`filterDefs` 仍是 5。真实利用里要么换新
  `ClassLoader`、要么换类名，本靶场靠 `up.sh` 重建容器来重置。
- **`@RequestParam` 参数名**：见 ②，必须显式写名字。
- **`libs/` 从哪来**：`up.sh` 从本地已有的 `sec-lab/shiro:1.0` 镜像解 fat jar，
  不联网、不需要 Maven。镜像不存在时先构建一次 shiro 靶场。
- **脚本重复跑**：`poc/run.py` 检测到 `lab-probe-filter` 已存在会提示先跑 `up.sh`，
  避免撞上上面那个 `LinkageError`。

---

## 10. 自己动手改（不改靶场源码结构）

四个练习，做完再回头看 `src/lab/MemShellInject.java`，理解会完全不一样。
每次改完重新跑 `./java-memshell/up.sh`（它会自动重编译）即可。

### 10.1 换一个 URL 映射

把 `MemShellInject.java` 里的 `map.addURLPattern("/*")` 改成 `"/admin/*"`，
重建后注入，再分别打：

```bash
curl -s -H "X-Lab-Probe: 1" http://127.0.0.1:19090/
curl -s -H "X-Lab-Probe: 1" http://127.0.0.1:19090/admin/x
```

预期：只有第二条命中。**为什么值得做**：真实内存马常绑一个不存在的冷门路径，
避免 `/*` 影响所有请求被察觉；但从防守视角看，多出来的 `filterMaps` 条目反而更显眼。

### 10.2 换特征头，看访问日志

把 `EvilFilter.java` 里的 `X-Lab-Probe` 换成 `X-Forwarded-For` 之类常见头，
重建、注入，然后：

```bash
docker logs --since 2m memshell-lab | tail -20
```

观察应用日志有没有任何异常。预期：什么都没有 —— 这正是"业务无感"的含义。

### 10.3 用标准 API 再试一次，确认顺序无关

先打 `/__lab/standard`，再注入，再打 `/__lab/standard`：

```bash
curl -s http://127.0.0.1:19090/__lab/standard
# ... 注入 ...
curl -s http://127.0.0.1:19090/__lab/standard
```

两次都返回 `standard API rejected`。**结论**：反射注册并没有"把门打开"，
它只是没走那道门。容器状态没被改变，标准 API 依旧不可用。

### 10.4 数一数检测侧的几个数

```bash
curl -s http://127.0.0.1:19090/__lab/scan | grep -c 'codeSource=(null'
curl -s http://127.0.0.1:19090/__lab/scan | grep -c 'codeSource=(file:'
docker exec memshell-lab sh -c 'jcmd 1 GC.class_histogram | grep -i evilfilter'
```

预期：注入后 `null` 计数为 1、`file:` 计数为 4、直方图里有 `evil.EvilFilter`；
`up.sh` 重置后 `null` 计数变回 0。这三个数就是一份最小可用的检测基线。

---

## 11. 检测与防御：从根治到兜底

一句话定性：**内存马绕开的是「查文件」，绕不开「查内存」**。
所以防守主线只有两条 —— 别让 RCE 发生，以及盯住运行时的类加载和注册表变化。

### 11.1 根治：堵上游入口

内存马是 RCE 的下游，堵住入口才是根治：

- 不反序列化不可信数据；升级 Shiro / Fastjson / 各类 gadget 依赖
- 升级 log4j、关闭 JNDI 远程 codebase、限制出站 LDAP / RMI / DNS
- 修表达式注入（SpEL / OGNL / 模板 SSTI），限制文件上传目录的可执行性
- 已有 webshell 查杀要跟上：真实攻击里"先落 JSP、注入内存马、再删 JSP"很常见，
  文件查杀在这里的价值是**抓上游**，不是抓内存马本身

### 11.2 运行时检测：查内存，不查磁盘

- **Filter / Servlet / Listener 基线**：定期把 `StandardContext.findFilterDefs()`、
  `findFilterMaps()` 导出来和启动时基线比对。本靶场 `/__lab/scan` 就是这个思路的
  最小实现
- **`codeSource=null` 是最强特征**：正常组件的类都来自某个 jar。
  由 `defineClass` 直接定义的类没有 `CodeSource`（L2、L4 实测）
- **JVM 全量类**：`jcmd <pid> GC.class_histogram` 看有没有不该存在的类名
  （L4 实测 `1  16  evil.EvilFilter`）；Arthas `sc` / `jad` 可以直接反编译
  JVM 里的类看字节码
- **Agent 型内存马**不新增任何组件，上面几条会全部失效。只能靠
  `Instrumentation` 重转换、SA Attach dump 字节码，或者对比类的字节码哈希
- **堆取证**：`jcmd <pid> GC.heap_dump` / `jmap -dump`，重启前先做

### 11.3 RASP / 运行时防护

- 拦截 `defineClass` + `addFilterDef` / `addFilterMapBefore` / `filterStart`
  这个**组合行为**。单独看每个方法都是合法 API，组合起来才是强特征
- 监控反射访问 `StandardContext`、`RequestMappingHandlerMapping`、
  `Instrumentation` 等敏感内部对象
- JDK 9+ 的模块强封装让 `setAccessible(true)` 打 `java.lang.ClassLoader` 变难
  （需要 `--add-opens java.base/java.lang=ALL-UNNAMED`），但**不是绝对防线**；
  本靶场是 JDK 8，`defineClass` 反射直接可用（L2 实测）
- 容器非 root、只读根文件系统、最小依赖：能砍掉大量落地和横向路径，
  但 9.⑤ 已经实测过，**挡不住纯内存注入**

### 11.4 排查清单

- 运行时 Filter / Servlet / Listener 列表 vs 启动基线，看数量和名字
- 有没有 `codeSource=null` 的类、类名是否出现在依赖清单里
- JVM 类直方图 / heap dump 里的陌生类
- 应用日志里的 `IllegalStateException: Filters cannot be added` 之类异常
  —— 有人试过标准 API 注册失败，是很好的入侵尝试痕迹
- 出站连接、反序列化入口、可疑上传文件（找上游 RCE）
- 注意**页面无回显、HTTP 200、状态码全正常**也可能已经中招（L3 实测）

### 11.5 怎么验收「真的清干净了」

别只看"重启过了"，要打一次看观测点。用本靶场的三个数就能把验收标准定下来：

- **通过**：像 L5 一样，`filterDefs=4`、`codeSource=null` 计数为 0、
  `jcmd` 直方图里无 `evil.EvilFilter`、带特征头返回 `business-ok`
- **不通过**：`filterDefs` 多出条目、`codeSource=null` 计数 ≥ 1、直方图里有陌生类
- **清完还要复查上游**：入口没修，重启完对方会再打一次

---

## 12. 练完怎么记

按这个模板记一条，比抄十页概念有用：

```
Java 内存马（Filter 型，不是漏洞，是 RCE 之后的驻留）
  两个支点：Servlet 3.0 动态注册（合法 API，但只在 STARTING_PREP 开放）
            + ClassLoader.defineClass(byte[])（类只在堆里，CodeSource=null）
  反射链：  ServletContext → ApplicationContext → StandardContext
  三步注册：addFilterDef → addFilterMapBefore → filterStart
  为什么选 Filter：早于 Servlet 路由（404 路径也能截）、/* 不新增 URL、
                    命中才处理其余放行、业务无感
  检测：    磁盘扫描必然失效（find 无结果、只读 FS 照样注入）
            查 filterDefs 基线 + codeSource=null + jcmd 类直方图 + heap dump
  生命周期：重启即消失 → 应急先 dump 堆再重启，再回头修上游 RCE
  一句话：  绕开「查文件」，绕不开「查内存」
```

**自测（能答出来才算过）**

1. 为什么说内存马不是漏洞？业务代码和依赖都没问题，它是怎么进去的？
2. `ServletContext.addFilter()` 为什么在应用跑起来之后会抛异常？反编译里是哪个判断？
3. `codeSource=null` 说明什么？为什么它比"文件名可疑"可靠得多？
4. 为什么 `/any/path` 这种 404 路径也会被内存马截获？
5. `evilClassOnClasspath=false` 和 `jcmd` 查到 `evil.EvilFilter` 矛盾吗？为什么？
6. `addFilterMapBefore` 到底把映射插到哪？要真正占住 index 0 该怎么做？
7. 只读根文件系统挡得住内存马吗？它真正挡住的是什么？
8. 重启之后还需不需要做别的事？为什么？
9. 说出三个运行时观测点，别只说"扫一下有没有 webshell 文件"。
10. Agent 型内存马为什么会让「比对 Filter 列表」这套检测失效？

---

## 附：命令速查

```bash
# 启动 / 重置 / 停止（每次 up.sh 都是干净状态）
./java-memshell/up.sh
./java-memshell/down.sh

# 一键演练 L0~L4（Python 标准库）
python3 java-memshell/poc/run.py

# 判题器：运行时注册表
curl -s http://127.0.0.1:19090/__lab/scan

# 标准 API 对照（应当永远 rejected）
curl -s http://127.0.0.1:19090/__lab/standard

# 手工注入
cd ~/代码库/靶场/java-memshell
B64=$(base64 -i attacker/evil/EvilFilter.class | tr -d '\n')
curl -s -G "http://127.0.0.1:19090/__lab/inject" --data-urlencode "b64=$B64"

# 命中 / 放行 / 404 路径
curl -s -H "X-Lab-Probe: 1" http://127.0.0.1:19090/
curl -s                      http://127.0.0.1:19090/
curl -s -H "X-Lab-Probe: 1" http://127.0.0.1:19090/any/path

# 磁盘视角（应当什么都查不到）
docker exec memshell-lab sh -c 'find / -iname "*EvilFilter*" 2>/dev/null'
docker exec memshell-lab sh -c 'touch /app/classes/.write-test'

# 内存视角（应当查得到）
docker exec memshell-lab sh -c 'jcmd 1 GC.class_histogram | grep -i evilfilter'
curl -s http://127.0.0.1:19090/__lab/scan | grep -c 'codeSource=(null'

# L5：重启后消失
docker restart memshell-lab
curl -s -H "X-Lab-Probe: 1" http://127.0.0.1:19090/
curl -s http://127.0.0.1:19090/__lab/scan | grep -E 'filterDefs=|filterMaps='

# 日志与排障
docker logs memshell-lab
docker logs --since 2m memshell-lab | grep -iE 'Exception|ERROR'
```
