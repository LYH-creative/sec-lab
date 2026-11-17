# Log4Shell · 组件/框架漏洞练习模块

CVE-2021-44228。和本仓库其他靶场不同，这里**漏洞不在自己写的代码里**，
而在引入的第三方组件 `log4j-core 2.14.1` 里：应用只是照常把 User-Agent
记进日志，整条 RCE 链条由组件自己完成。

独立编排，不并入根目录 `docker-compose.yml`，不影响现有八个靶场。

**配套练习手册**：[Log4Shell-练习手册.md](Log4Shell-练习手册.md) —— 原理逐层拆解、
四关实战（含真实输出）、认知纠错（含错误结论原文与实测反证）、
动手练习、修复建议、自测题与命令速查。

## 起停

```bash
./log4shell/up.sh                       # 构建 + 启动 + 初始化（含 buildx 回退）

python3 log4shell/poc/01_probe.py       # 一关一关练
python3 log4shell/poc/verify.py         # 或一键回归

docker compose -f log4shell/compose.yml down
```

只重做初始化（清事件、等服务）用 `./log4shell/setup.sh`，可重复跑。

## 端口

| 宿主 | 容器内 | 配置 |
|---|---|---|
| 127.0.0.1:19080 | 8080 | log4j 2.14.1 + `-Dcom.sun.jndi.ldap.object.trustURLCodebase=true` |
| 127.0.0.1:19081 | 8081 | log4j 2.14.1 + JDK 默认（禁止远程 codebase） |
| 127.0.0.1:19082 | 8082 | log4j 2.17.1 |
| 127.0.0.1:19089 | 8000 | 攻击者 HTTP：`.class` 托管 / `/events` / `/reset` |
| — | 1389 | 攻击者 LDAP，只在容器网络内可达 |

payload 里写死的 `ldap://attacker:1389` 靠 `l4sh-net` 上的 network alias 解析。

## 关卡

| 关 | 入口 | 练什么 | flag |
|---|---|---|---|
| L1 | 19080 `/` | `${env:}` 嵌套进 JNDI URL，靠 LDAP 查询 DN 外带环境变量，不 RCE | `flags/l1.flag` |
| L2 | 19080 `/` | javaNamingReference → 远程 codebase → 目标 JVM 执行静态块 | `flags/l2.flag` |
| L3 | 19080 `/filtered` | `${::-j}` 语法把关键字拼回来，绕过关键字黑名单 | `flags/l3.flag` |
| L4 | 19081 / 19082 | 对照：JDK 加固只挡住远程类加载，升级 log4j 才根治 | 无（认知对照） |

flag 文件只读挂载进 app 容器，只有真的在目标 JVM 里执行了代码（L2/L3）
或真的外带成功（L1）才拿得到。

## 复现时踩过的坑

- **JDK 8u191 / 11.0.1 起默认禁止 JNDI 远程 codebase**。现在能拉到的
  `eclipse-temurin:8-jdk` 都远新于它，不显式加
  `-Dcom.sun.jndi.ldap.object.trustURLCodebase=true` 会表现为"有回连但打不出 RCE"。
  8080 是还原 2021 年环境，8081 保留默认值专门做对照。
- **没有 log4j2.xml 就打不动**：log4j-core 无配置时默认 root level 是 ERROR，
  `LOG.info()` 连日志事件都不产生，lookup 根本不会跑。
- **`HttpServer` 默认单线程**，JNDI 是同步调用，一个卡住的请求会堵死后续所有请求，
  必须给线程池。
- **恶意类要用 JDK 8 编译**。宿主 javac 17 编出来的 class 版本 61，
  JDK 8 加载会报 `UnsupportedClassVersionError`，所以 attacker 镜像用多阶段构建。
- **`javaFactory` 必须实现 `javax.naming.spi.ObjectFactory`**。JNDI 会把下载来的类
  强转成这个接口；不实现时静态块照样执行、flag 照样能拿到，但目标日志里会甩出
  一整屏 `ClassCastException`。实测改成实现接口、`getObjectInstance` 返回 null 后，
  重启 app 再打一次，日志里 0 异常。真实利用要的就是这种"安静"。
- **L3 的混淆 payload 会触发 9 次完整利用链**（本机实测）。log4j 对嵌套
  `${...}` 做多轮递归替换，每轮都重新执行一次 JNDI lookup，于是
  bind → search → 下载 class → 回传 flag 整条链重复 9 遍。这不是脚本写错，
  是 2.14.1 的真实行为：混淆绕过在真实环境里会把请求放大、把告警打爆。
  `poc/_util.py` 的 `show_events()` 按语义合并成 `×9`，原始次数仍可在 `/events` 里查。
- **L1 的 LDAP 服务故意不返回 `javaCodeBase`**，否则探测阶段就会顺手触发
  L2 的 RCE，关卡边界就没了。

构建时若报 `buildx: ... operation not permitted`（本机实测遇到过），和根
`README.md` 里记的是同一个问题：`~/.docker/buildx` 不可写。已经把三级回退
封装进 `./log4shell/up.sh`，平时直接用它就行。想手动复现第二层：

```bash
BUILDX_CONFIG="$(mktemp -d)/buildx" docker compose -f log4shell/compose.yml up -d --build
```

## 安全声明

- 所有端口只绑 `127.0.0.1`；2.14.1 那一路是**真的能远程加载类执行代码**的，
  不要改成 `0.0.0.0`，别放进有多人使用的网络。
- `L2.class` / `L3.class` 是靶场专用的最小载荷，只读取容器内的 flag 并回传。
- jar 沿用本仓库约定：构建时从 Maven Central 拉取（失败退阿里云镜像），
  不把第三方 jar 提交进仓库。
- 仅用于本地学习或已获授权的测试。
