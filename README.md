# SecLab · 安全靶场合集

八个靶场、23 个容器（默认启动 20 个，ARP 按需），一条命令全起来，
全部只绑本机 `127.0.0.1`。

覆盖 Web 常规漏洞、PHP / Java 反序列化、XXE、Gopher SSRF、JWT 绕过、
webshell 应急排查、沙箱逃逸，以及网络层的 ARP 欺骗。每个靶场都自带纯标准库的
验证脚本——先自己做，卡住了再拿来对答案。

```
$ ./lab.sh up
[+] 目录与 flag 就绪
[+] gopher L5 flag 已写入 MySQL
[+] gopher L3 flag 已写入 Redis
[+] DVWA 数据库已初始化
[+] sandbox L6 flag 已铺到宿主 /lab-escape/

  导航页        http://127.0.0.1:8880/
  DVWA          http://127.0.0.1:8888/        admin / password
  ...
  Sandbox Escape http://127.0.0.1:8900/       L1~L4 页面 · L5/L6 终端
```

---

## 包含什么

| # | 靶场 | 入口 | 内容 | 难度 |
|---|---|---|---|---|
| 0 | **导航页** | http://127.0.0.1:8880/ | 所有靶场的入口一览 | — |
| 1 | **DVWA** | http://127.0.0.1:8888/ | 18 个漏洞模块 × 4 档难度 | 基础 |
| 2 | **反序列化** | http://127.0.0.1:8890/ | PHP 4 关 + Java CC6 | 进阶 |
| 3 | **XXE** | http://127.0.0.1:8895/ | 5 关递进 + 修复对照 | 中 |
| 4 | **Gopher SSRF** | http://127.0.0.1:8896/ | 6 关，打通 Redis / MySQL / php-fpm | 进阶 |
| 5 | **JWT** | http://127.0.0.1:8898/ | 4 关 + 修复对照 | 中 |
| 6 | **webshell-hunt** | http://127.0.0.1:8899/ | 9 处后门 + 1 处诱饵 | 应急响应 |
| 7 | **Sandbox Escape** | http://127.0.0.1:8900/ | 沙箱逃逸 6 关（语言级 4 + 容器级 2） | 进阶 |
| 8 | **ARP 欺骗** | 终端 | 7 个实验，完整中间人 | 网络 |

合计 42 个关卡 / 后门 / 实验。

---

## 环境要求

- **Docker Engine 20.10+**，含 **Compose v2**（`docker compose`，不是老的 `docker-compose`）
- 内存建议 **6 GB 以上**给 Docker（20 个容器同时跑）
- 磁盘 **6 GB** 左右（镜像 + 数据库卷）
- 首次启动需要联网拉镜像、构建镜像（Java 那个还要从 Maven Central 下 jar）

支持 macOS（Intel / Apple Silicon）、Linux、Windows（WSL2 或 Git Bash）。

---

## 快速开始

### 1. 下载

```bash
git clone https://github.com/LYH-creative/sec-lab.git
cd sec-lab
```

没有 git 就下载 ZIP 解压，效果一样。

### 2. 启动

```bash
chmod +x lab.sh
./lab.sh up
```

脚本会依次做四件事：修正上传目录权限 → 铺 flag → 构建并启动容器 →
灌数据（MySQL / Redis 的 flag、DVWA 建库）。首次运行视网络 5~10 分钟。

只想用原生命令、不要脚本的初始化：

```bash
docker compose up -d --build
```

容器照样能跑，但 Gopher 的 L3/L5 flag 和 DVWA 的数据库表需要手动灌
（`./lab.sh init` 可以补做这一步）。

### 3. 打开

浏览器访问 **http://127.0.0.1:8880/**，导航页里有全部入口。

Windows 下 `lab.sh` 需要 Git Bash 或 WSL；也可以直接在 PowerShell 里跑
`docker compose up -d --build`，代价是少了自动灌数据那一步。

---

## 命令一览

```bash
./lab.sh up               # 启动全部 Web 靶场
./lab.sh up all           # 连 ARP 一起启动（额外构建网络实验镜像）
./lab.sh down             # 停止（数据保留）
./lab.sh restart          # 重启
./lab.sh status           # 容器状态 + 宿主机端口占用
./lab.sh logs [服务名]    # 跟踪日志，如 ./lab.sh logs gopher-web
./lab.sh shell <服务名>   # 进容器，如 ./lab.sh shell webshell-hunt
./lab.sh init             # 只重做初始化（flag / 权限 / 数据库）
./lab.sh reset            # 彻底重置：删容器和数据库卷后重建
./lab.sh answer [靶场]    # 打印答案速查
./lab.sh build            # 只构建镜像
```

答案也可以直接看 [`docs/answers.md`](docs/answers.md)，或者：

```bash
./lab.sh answer gopher    # 只打印 Gopher 那一章
```

---

## 各靶场说明

每个靶场目录里都有独立的 `README.md`，写的是关卡设计、踩过的坑和原理。
下面只说入口和该关注什么。

### DVWA · 8888

最经典的故意不安全站点。登录 `admin / password`，左侧菜单选模块，
底部 `View Source` 看当前难度对应的源码。

建议路径：`sqli` → `sqli_blind` → `xss_r/s/d` → `upload` → `exec` → `fi`。
每关在 low / medium / high / impossible 之间切换，对照源码差异比刷关更有用。

配套的两个提取脚本演示了怎么把注入变成可编程的数据提取：

```bash
cd dvwa && python3 error_extract.py     # 报错注入：三种通道 + 分难度姿势
cd dvwa && python3 blind_extract.py     # 布尔盲注：二分法逐字符取
```

### 反序列化 · 8890 / 8891 / 8892

三个端口对应三个运行时，因为有些利用点跟版本强绑定：

- `8890` PHP 8.1：L1 魔术方法、L2 POP 链、L3 private 属性
- `8891` PHP 7.4：L4 phar 元数据（**8.x 上这个触发点已经失效**）
- `8892` Java：`POST /api/import` 直接收序列化字节流，CC6 链

### XXE · 8895

五关递进：有回显 → 盲打外带 → 报错型 → 内网 SSRF → SVG 上传。
L4 的目标 `xxe-internal` 不映射端口，宿主机 `curl http://internal` 会
DNS 失败——那是真隔离，得让 web 容器代你去请求。

### Gopher SSRF · 8896

六关都在同一个 SSRF 入口上，目标分别是对宿主机暴露的 gopher 服务、
内网 302 网关、未授权 Redis（读 / 写）、免密 MySQL、裸 php-fpm。
每关的难点都在「手工拼协议包」，不在 SSRF 本身。

L1 的靶子额外暴露在 `gopher://127.0.0.1:7070`，方便先用 curl 直观看协议长什么样。

### JWT · 8898

登录账号 `alice / alice123`（普通用户），目标是造出 `role=admin` 的令牌。
四关分别对应弱密钥、`alg:none`、RS256→HS256 算法混淆、`kid` 路径穿越。
`safe.php` 是修复对照页，把造好的令牌粘进去能看到四条各自怎么被挡。

### webshell-hunt · 8899

反过来的一关：不给入口，给你一台「已经被入侵」的服务器。9 处后门藏在
25 个文件里，还有 1 处诱饵专门用来检验会不会误报。

```bash
docker exec -it webshell-hunt bash
cd /var/www/html && ls -la
```

**别急着开浏览器点**，那会污染 `access.log`——日志本身是第一证据源。
排查七步法和完整答案在 `webshell-hunt/answer/ANSWERS.md`。

### Sandbox Escape · 8900

六关，六种隔离手段，六个洞。前四关在页面里直接打（Node `vm`、Python
关键字黑名单、pickle 白名单、chroot），后两关是真正的容器逃逸：

```bash
docker exec -it sbox-sock bash     # L5：容器里挂着宿主的 docker.sock
docker exec -it sbox-priv bash     # L6：privileged + pid=host
```

L5 的目标容器 `sbox-vault` 不开端口、不给 shell，只能从 socket 摸进去；
L6 的 flag 在宿主根目录 `/lab-escape/`，容器自己的 `/` 里看不到。

```bash
python3 sandbox-escape/poc/verify.py    # L1~L4 一键验证
```

**注意**：L5 挂的是宿主机真实的 docker.sock，等于把 Docker 的完整控制权
交出去；L6 会往宿主根目录写一个 `/lab-escape/`。只在你自己机器上跑，
清理由 `sandbox-escape/setup.sh --clean` 负责。

### ARP 欺骗 · 终端

```bash
./lab.sh up all
docker exec -it arp-victim ip route
docker exec -it arp-victim ip neigh
```

三容器同 bridge：网关 `172.28.0.2`、受害者 `172.28.0.3`、攻击机 `172.28.0.4`。
受害者默认路由指向网关，被投毒后流量先经过攻击机。
7 个实验从「为什么 arpspoof 跑了没反应」到「自己做检测」，
原理拆解在 `arp/PRINCIPLE.md`。

---

## 端口占用

| 端口 | 服务 | 说明 |
|---|---|---|
| 8880 | portal | 导航页 |
| 8888 | dvwa | admin / password |
| 8890 | deser-php | PHP 8.1，L1~L3 |
| 8891 | deser-php74 | PHP 7.4，L4 phar |
| 8892 | deser-java | Java CC6 |
| 8895 | xxe-web | XXE 五关 |
| 8896 | gopher-web | Gopher 六关 |
| 8898 | jwt-web | JWT 四关 |
| 8899 | webshell-hunt | 应急响应 |
| 8900 | sbox-web | 沙箱逃逸 L1~L4 |
| 7070 | gopher-legacy-public | L1 的 gopher 靶子 |

端口被占用时，改 `docker-compose.yml` 里对应服务的 `ports` 左侧数字即可。
容器内部的端口不要动，源码里写死了。

---

## 目录结构

```
sec-lab/
├── docker-compose.yml     # 全部靶场的编排（唯一的启动入口）
├── lab.sh                 # 统一管理脚本
├── README.md              # 本文件
├── docs/
│   └── answers.md         # 全部 flag + 解题思路
├── portal/html/           # 导航页（静态，nginx 直接托管）
│
├── dvwa/                  # 1. DVWA（官方镜像 + 独立 mariadb）
├── deserialization/       # 2. PHP / Java 反序列化
├── xxe/                   # 3. XXE 五关
├── gopher/                # 4. Gopher SSRF 六关
├── jwt/                   # 5. JWT 四关
├── webshell-hunt/         # 6. webshell 排查
├── sandbox-escape/        # 7. 沙箱逃逸六关
└── arp/                   # 8. ARP 欺骗
```

每个靶场目录都保留了自己的 `compose.yml`，可以单独启动（见下一节）。

---

## 单独启动某一个靶场

集成编排是默认用法，但每个靶场也可以独立跑——调试关卡时更快：

```bash
cd xxe && ./setup.sh          # 或 docker compose up -d --build
cd gopher && ./setup.sh       # 这个会顺带灌 flag
cd jwt && ./setup.sh
cd sandbox-escape && ./setup.sh    # 这个会顺带把 L6 的 flag 铺到宿主
cd dvwa && ./dvwa.sh up
cd arp && ./run.sh
cd webshell-hunt && ./reset.sh
```

注意：子目录的 `compose.yml` 和根目录的 `docker-compose.yml` **用了相同的
容器名**。同时启动会冲突（`Conflict. The container name is already in use`），
先 `./lab.sh down` 再进子目录起。

---

## 常见问题

**Q：`./lab.sh up` 卡在拉镜像 / 构建很久。**
首次要拉 nginx、mariadb、redis、python、php 等多个基础镜像，加上构建
PHP 和 Java 靶场。国内网络可以给 Docker 配镜像加速器。第二次启动是秒级。

**Q：构建报 `buildx: ... operation not permitted`，或者构建一路无输出、像卡住了。**
两种不同的问题，`lab.sh` 现在按顺序试三层：

1. 默认 buildx；
2. `BUILDX_CONFIG` 指到临时目录再试 —— 大部分"operation not permitted"
   都是 buildx 写不了 `~/.docker/buildx`（受限工作目录、在容器里跑），
   换个状态目录就好，速度不变；
3. 最后才退 `DOCKER_BUILDKIT=0`（经典 builder）。这一层在部分环境下
   **不报错也不输出，直接挂着**，所以它排在最后。

想手动复现第 2 层：

```bash
BUILDX_CONFIG=$(mktemp -d)/buildx docker compose up -d --build
```

**Q：Sandbox Escape 的 L6 读不到 `/lab-escape/l6.flag`。**
这个 flag 不在容器里，是 `./lab.sh init`（或 `up`）时用一次性容器铺到
宿主根目录的。纯 `docker compose up` 启动不会有它，补跑一次初始化：

```bash
./lab.sh init
docker exec sbox-priv cat /proc/1/root/lab-escape/l6.flag
```

macOS / Windows 上这里的"宿主"是 Docker Desktop 的 Linux VM。

**Q：DVWA 页面报 `Could not connect to the database` / 提示建库。**
数据库容器还在初始化，等 10 秒刷新；或者 `./lab.sh init` 重跑初始化。
彻底重来：`./lab.sh reset`。

**Q：Gopher 的 L3 / L5 读不到 flag。**
这两个 flag 是**容器起来之后**才灌进去的。跑 `./lab.sh init` 补灌。
纯 `docker compose up` 启动的话一定会缺这一步。

**Q：XXE 的 L2 盲打收不到数据。**
需要容器能回连宿主机。Docker Desktop（macOS / Windows）默认支持
`host.docker.internal`；Linux 上要手动加：

```bash
# 在 docker-compose.yml 的 xxe-web 服务下加
extra_hosts:
  - "host.docker.internal:host-gateway"
```

或者用 `OOB_HOST=<宿主机局域网IP>` 环境变量跑脚本。

**Q：JWT 页面签名一直失败 / 令牌签名段是空的。**
宿主机上私钥是 `600`，bind mount 进去 `www-data` 读不到，
`openssl_sign` 会静默失败。`docker-compose.yml` 里已经在启动命令中
`chmod 644`，如果手动改过权限，重跑 `./lab.sh init`。

**Q：`./lab.sh up all` 报 `Pool overlaps with other one on this address space`。**
ARP 靶场的 IP 在脚本里写死了 `172.28.0.0/24`，这个网段被别的 Docker 网络占了。
`lab.sh` 会自动清理旧靶场项目遗留的网络（`arp-lab_arpnet` 等）；
如果占用方是别的项目（比如某个 VPN），只能改网段：

```bash
docker network ls                       # 找到占 172.28 的网络
docker network inspect <名字>           # 确认是不是你自己的
```

确认可以动之后 `docker network rm <名字>`，或者把 `docker-compose.yml` 里
`arp-net` 的 `subnet` 连同 `arp/scripts/*.py`、`arp/README.md` 里的 IP 一起改掉。

**Q：`./lab.sh up` 报 `container name is already in use`。**
以前用「单靶场模式」（进子目录 `docker compose up`）起过同名容器。
`lab.sh` 现在会自动清理不属于本项目的同名容器；如果还有残留：

```bash
docker rm -f dvwa dvwa-db deser-php xxe-web jwt-web webshell-hunt gopher-web
```

**Q：端口被占用。**
`./lab.sh status` 能看到宿主机上这些端口的占用情况，改
`docker-compose.yml` 里对应服务的 `ports` 左侧数字。

**Q：想从局域网另一台机器访问。**
默认只绑 `127.0.0.1`。改成 `LAB_BIND=0.0.0.0 ./lab.sh up` 会监听所有网卡——
**这意味着同网段任何人都能访问这些带真实漏洞的站点，包括 DVWA 的命令执行。**
除非是隔离的实验网络，否则别这么干。

**Q：Apple Silicon 上 Java 容器起不来。**
`eclipse-temurin:8-jdk` 有 arm64 版本，正常可用。如果拉不到，装 Rosetta
或改用 `--platform linux/amd64`（会慢一些）。

---

## 安全声明

- 所有靶场只绑定 `127.0.0.1`，默认出不了本机。
- 容器里跑的是**故意留有漏洞**的代码，包括命令执行、文件上传、反序列化。
  **不要**把端口暴露到公网、公司内网或任何非你控制的环境。
- 这些环境仅用于本地学习与**获得授权**的测试。
  对任何未授权的系统使用其中的技术，后果自负。
- **Sandbox Escape 这一套比别的靶场更"出圈"**：
  `sbox-sock` 挂载了宿主真实的 `docker.sock`（连上就等于 root@宿主，
  能起 `--privileged -v /:/host` 的容器），`sbox-priv` 是 `privileged` + `pid: host`，
  而 L6 会往宿主根目录写 `/lab-escape/`。别在有多人使用或存有重要数据的
  机器上跑；清理用 `sandbox-escape/setup.sh --clean`。
  macOS / Windows 上这些"宿主"是 Docker Desktop 的 Linux VM，不碰你的 macOS。
- DVWA 镜像是第三方项目（`ghcr.io/digininja/dvwa`），其余代码在本仓库内。

---

## 卸载

```bash
./lab.sh down                  # 停容器，保留数据
docker compose --profile net down -v   # 连数据卷一起删
docker image prune -f          # 清掉不再使用的镜像层
```

彻底清掉本项目构建的镜像：

```bash
docker images --format '{{.Repository}}:{{.Tag}}' | grep -E 'sec-lab/|arp-lab' | xargs -r docker rmi
```

---

## 许可

MIT。见 [LICENSE](LICENSE)。

靶场代码用于教学，欢迎拿去改。如果发现关卡设计有问题（比如某关存在
非预期解法），开 issue 说明复现步骤。

---

作者：[lyh-blogs.top](https://lyh-blogs.top) · [GitHub @LYH-creative](https://github.com/LYH-creative)
