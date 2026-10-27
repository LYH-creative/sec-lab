# ARP 欺骗：原理与脚本拆解

配套 `README.md` 的实操实验看。这份文档只讲两件事：**协议为什么能被骗**、**脚本每一行在干什么**。

---

## 一、ARP 在解决什么问题

一台主机要发包给同网段的另一台主机，IP 只是逻辑地址，真正塞进以太网帧头里的是 MAC 地址。所以内核手里必须有「IP → MAC」的对照表，这张表就是 ARP 缓存（`ip neigh` 看的就是它）。

ARP 的职责就一句话：**已知 IP，问出 MAC**。

它工作在二层，没有 IP 头，不经过路由，出不了本网段。这也决定了 ARP 欺骗的作用范围——只能骗同一个广播域里的机器。

## 二、报文长什么样

ARP 报文固定 28 字节，套在以太网帧里，加上 14 字节帧头，抓包看到的就是 42 字节：

```
┌──────────────── Ether 帧头（14 字节）────────────────┐
│ dst MAC (6) │ src MAC (6) │ 类型 0x0806 (2)          │
├──────────────── ARP 报文（28 字节）──────────────────┤
│ 硬件类型 (2)  │ 协议类型 (2)  │ 硬件长度 (1) │ 协议长度 (1) │
│ 操作码 (2)    │ 发送方 MAC (6) │ 发送方 IP (4)             │
│ 目标 MAC (6)  │ 目标 IP (4)                                │
└──────────────────────────────────────────────────────┘
```

各字段的实际取值：

- **硬件类型** `0x0001`，以太网
- **协议类型** `0x0800`，IPv4
- **硬件长度** `6`（MAC 6 字节）、**协议长度** `4`（IP 4 字节）
- **操作码** `1` = 请求（who-has），`2` = 应答（is-at）
- **发送方 MAC / IP**：谁发的
- **目标 MAC / IP**：问谁的

关键点：**ARP 报文里的「发送方 MAC」和以太网帧头里的「源 MAC」是两个独立字段**，正常主机填成一样，攻击者可以填成不一样——这是后面很多花招的来源。

## 三、一次正常交互（实测）

把受害者的缓存清掉，然后 ping 网关，在受害者上抓包：

```bash
docker exec arp-victim ip neigh del 172.28.0.2 dev eth0
docker exec arp-victim tcpdump -l -e -n -c 4 arp &
docker exec arp-victim ping -c1 172.28.0.2
```

实测输出：

```
3e:50:33:43:99:0f > ff:ff:ff:ff:ff:ff, ARP, Request who-has 172.28.0.2 tell 172.28.0.3
fa:b3:c4:3c:fd:eb > 3e:50:33:43:99:0f, ARP, Reply 172.28.0.2 is-at fa:b3:c4:3c:fd:eb
```

逐字段读第一行：

- 帧的**目的 MAC 是 `ff:ff:ff:ff:ff:ff`**（广播）——因为还不知道网关 MAC，只能全喊
- `who-has 172.28.0.2` 是问题
- `tell 172.28.0.3` 是「我知道自己的地址，回我就行」

第二行：

- 帧的**目的 MAC 是 `3e:50:33:43:99:0f`**（单播）——现在知道问的人是谁了
- `is-at fa:b3:c4:3c:fd:eb` 就是答案

**请求是广播、应答是单播**——这个差异后面会反复用到。它直接决定了「检测器为什么必须装在受害者上」。

## 四、四个设计缺陷

ARP 是 1982 年的协议（RFC 826），那时是互相信任的学术网络，安全不是设计目标。它留下了四个洞：

- **没有认证**：报文里没有任何签名字段，谁发都算数。你说你是网关，没人会验证
- **没有状态**：主机收到一个 `is-at` 应答，不会检查「我刚刚问过吗」。不问也接受
- **有缓存**：接受之后会记一段时间，这段时间里所有流量都按这个错误映射走
- **请求靠广播**：广播域里每台机器都能看到谁在问什么，也都能抢答

第一条决定了「能不能骗」，第二条决定了「骗起来多容易」，第三条决定了「骗一次能管多久」。

## 五、缓存状态机 —— 为什么有时骗不动

这是整个靶场里最容易卡住的点，值得单独讲。

Linux 的邻居条目（包括 ARP）是有限状态机：

```
  (不存在)
      │ 要发包，先发 who-has
      ▼
  INCOMPLETE ──── 收到 is-at ────► REACHABLE
                                       │
                                       │ 一段时间没通信（约 30 秒）
                                       ▼
                                    STALE ◄──── 攻击窗口
                                       │
                                       │ 真的要用它发包了
                                       ▼
                                    DELAY ──5 秒──► PROBE ──► 重发 who-has
```

各状态的差别：

- **REACHABLE**：最近确认过可达，内核认为这个映射是可信的
- **STALE**：条目还能用，但「可能过期了」，下次发包前要重新确认
- **DELAY / PROBE**：正在确认的过程中
- **PERMANENT**：手动钉死的，永远不老化（防御用）

**关键规则**：内核收到一个「非请求的」ARP 应答时，如果条目正处在 `REACHABLE`，会倾向于忽略它。理由是——你最近才验证过，凭什么一个陌生包就能改？

只有条目落到 `STALE`（内核认为「这个信息可能旧了」），新的应答才会被认真对待。

所以真实的 ARP 攻击是这样的：

1. 攻击机持续发伪造应答
2. 前几十秒受害者不理它（`REACHABLE`）
3. 条目老化成 `STALE`
4. 这一刻收到的伪造应答被接受，缓存被改写
5. 改写后又变 `REACHABLE`，攻击者继续发，维持住

**这就是为什么 arpspoof 必须一直跑**。不是刷屏，是在蹲那个窗口。

想立刻看到效果，手动把条目改成 `STALE`：

```bash
docker exec arp-victim ip neigh change 172.28.0.2 dev eth0 nud stale
```

`ip neigh` 最后一列就是状态，实验时养成习惯盯着它。

## 六、三种欺骗形态

**单向**：只骗受害者，让它以为网关的 MAC 是攻击机。

- 受害者的出站流量先到攻击机
- 回程流量直接从网关发给受害者（网关的缓存没被动过）
- 结果：**只能看到请求，看不到响应**
- 用途：偷 HTTP 明文凭据、Cookie、URL 参数——请求里全都有

**双向**：两个方向都骗。

- 对受害者说「网关是我」
- 对网关说「受害者是我」
- 结果：所有包都先经过攻击机，**完整中间人**
- 前提：攻击机必须开 `ip_forward`，否则就是断网

**冒充网关骗全网段**：对广播域里所有主机发「网关是我」，一次骗一片。原理一样，只是目标从单台变成整个网段（并发操作也变成一台台来）。

## 七、ip_forward 到底管什么

`net.ipv4.ip_forward` 控制内核要不要转发「目的地不是自己」的包。

- **= 0**：包到了攻击机，发现目标 IP 不是自己，直接丢弃 → 受害者断网。这是**断网型 DoS**，也是很多人「打了一半网就没了」的原因
- **= 1**：包照原样转发出去，链路通，攻击机只是中间站 → **中间人**

容器里这个参数改不了（`sysctl: permission denied`），因为要在创建 netns 时才定，所以写进了 `compose.yml` 的 `sysctls`。

顺带一提，转发时内核会把 TTL 减 1。所以「TTL 异常」在某些检测场景里是一条线索。

## 八、脚本拆解：arpspoof.py

### 整体结构

```
main()
 └─ ArpSpoofer(...).run()
     ├─ resolve()      问出两个真实 MAC（一次性）
     ├─ 循环 poison_once()  每 2 秒一轮，双向各发一个伪造应答
     └─ KeyboardInterrupt → restore()  把正确映射发回去
```

三个函数各管一件事，`poison_once` 和 `restore` 用的是同一个 `make_reply`，区别只是「声称的 MAC 是谁」。

### arp_resolve()：怎么问出真实 MAC

```python
ans, _ = srp(
    Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip),
    iface=iface, timeout=timeout, verbose=False,
)
for _, rcv in ans:
    return rcv[ARP].hwsrc
```

拆开看：

- `Ether(dst="ff:ff:ff:ff:ff:ff")` —— 目的 MAC 全 f，就是广播
- `/ ARP(pdst=ip)` —— 斜杠是 scapy 的「叠加」操作符，把 ARP 报文塞进以太网帧的载荷里
- `ARP(pdst=ip)` 只填了目标 IP，`op` 默认是 1（请求），其余字段 scapy 自动补
- `srp` = send and receive at layer 2（**s**end **r**eceive **p**acket，二层版）。它发包、收包、把「发了什么」和「收到了什么」配对返回
- 返回值是 `(answered, unanswered)` 两个列表，`for _, rcv in ans` 只关心收到的
- `rcv[ARP].hwsrc` 取应答里的发送方 MAC，这就是答案

为什么不用 scapy 自带的 `getmacbyip()`：那个函数的参数名在不同版本里改过（2.8 里就没有 `iface` 参数，传了直接 TypeError）。自己写一遍十几行，稳定，而且过程全透明。

### make_reply()：伪造应答的核心

```python
return Ether(dst=eth_dst, src=eth_src) / ARP(
    op=2, hwsrc=eth_src, psrc=claimed_ip,
    hwdst=target_mac, pdst=target_ip,
)
```

五个参数，逐个对应到报文：

- `eth_dst` → 帧头目的 MAC，**写具体 MAC 就是单播**，只送到这一台
- `eth_src` → 帧头源 MAC，填攻击机自己的
- `op=2` → 这是应答（is-at），不是请求。受害者不会去核对「我问过吗」
- `hwsrc=eth_src` → **报文里的发送方 MAC 必须等于帧头的源 MAC**。填不一致等于自己举报自己，有些主机/IDS 会直接告警
- `psrc=claimed_ip` → **这是整个骗局的核心**：声称自己是那个 IP
- `hwdst` / `pdst` → 收件人的 MAC 和 IP

为什么用单播不用广播：广播会让整个网段的所有机器都更新缓存（动静大、容易被发现），而单播只有目标主机收得到——**顺带让同网段的第三方监控完全看不到这次攻击**。

### poison_once()：为什么要发两次

```python
# 方向一：骗受害者
make_reply(eth_dst=victim_mac, eth_src=my_mac,
           claimed_ip=gateway_ip, target_ip=victim_ip, target_mac=victim_mac)

# 方向二：骗网关
make_reply(eth_dst=gateway_mac, eth_src=my_mac,
           claimed_ip=victim_ip, target_ip=gateway_ip, target_mac=gateway_mac)
```

两次调用的参数完全对称，只有「骗谁」和「冒充谁」互换：

- 第一次：发给受害者，声称自己是网关 IP
- 第二次：发给网关，声称自己是受害者 IP

只做第一次，就是单向——回程流量不经过攻击机。

### restore()：为什么必须写

```python
for _ in range(5):
    sendp(make_reply(eth_dst=victim_mac, eth_src=gateway_mac,
                     claimed_ip=gateway_ip, ...))
    sendp(make_reply(eth_dst=gateway_mac, eth_src=victim_mac,
                     claimed_ip=victim_ip, ...))
    time.sleep(0.3)
```

和毒化代码长得几乎一样，唯一区别：**`eth_src` 换成了对方的真实 MAC**，也就是「用真实身份发一个正确的应答」。

不写这段的后果：攻击机一退出，受害者缓存里网关 MAC 还是攻击机的，所有流量发向一个已经不在的地址，直接断网，直到条目老化（最长几分钟）。

**必须双向恢复**，只恢复一边会导致「攻击停了，受害者还是不通」——这个坑在 README 踩坑记录里专门写了。

连发 5 次是因为 UDP 式的尽力而为，发一次可能丢。

### run()：循环和间隔

```python
while True:
    self.poison_once()
    round_no += 1
    if round_no % 5 == 1:
        print(...)
    time.sleep(self.interval)
```

`interval` 默认 2 秒。这个值的取舍：

- 太慢（>10 秒）：受害者条目老化后可能自己重新问到正确 MAC，欺骗断了
- 太快（<0.1 秒）：大量无用流量，容易被流量分析发现

2 秒是常见默认值。`round_no % 5 == 1` 只是让日志别刷屏。

`except KeyboardInterrupt` 捕获 Ctrl-C，转去 `restore()`——这就是「优雅退出」在这个场景的实际意义。

## 九、脚本拆解：detect_arp_spoof.py

### 整体结构

```
main()
 ├─ build_baseline()       开局问一次真 MAC，存进全局字典 baseline
 └─ sniff(prn=on_packet)   每收到一个包调用一次 on_packet
     └─ on_packet()        三层过滤，对不上就告警
```

和 `arpspoof.py` 正好相反：攻击脚本是**主动造包**（自己决定什么时候发什么），检测脚本是**被动等包**（内核收到什么就处理什么）。一个是循环 push，一个是回调 callback。

### 为什么检测器必须装在受害者上

回到第三节的实测：**ARP 应答是单播的**。

攻击机发的伪造应答，帧头目的 MAC 直接写成受害者的 MAC。在真实交换机上，这个帧只会被转发到受害者那个端口，同网段的第三台机器根本收不到。

所以传统的「旁路部署 arpwatch 抓全网的 ARP」在这个场景里是瞎的——它只能看到广播的请求，看不到单播的谎言。**只有受害者自己的网卡能看到骗它的那个包。**

（Docker 的 bridge 行为和真实交换机不完全一样，但结论不变：别指望第三方机器帮你检测。）

### build_baseline()：先拿到「真相」

```python
ans, _ = srp(
    Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=watch_ip),
    iface=iface, timeout=2, verbose=False,
)
for _, rcv in ans:
    mac = rcv[ARP].hwsrc
    baseline[watch_ip] = mac
    return
```

逐行看：

- `Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=watch_ip)` —— 和 `arpspoof.py` 里 `arp_resolve()` 做的是同一件事：造一个广播的 who-has。这里故意复制逻辑而不是 import，因为两个脚本要能各自独立拷走使用
- `srp` 返回两个列表 `(answered, unanswered)`，我们只用 `ans`
- `for _, rcv in ans: return` —— **只取第一个应答就返回**。局域网里同一个 IP 只该有一台机器应答，先到的就是它。如果此刻有攻击者在抢答，说明已经在被攻击了，那基线本来也不该信
- `baseline[watch_ip] = mac` —— 写进模块顶层的全局字典

失败处理：

```python
sys.exit(f"[!] 建立基线失败：{watch_ip} 没有回应 ARP")
```

`sys.exit(字符串)` 会把字符串打到 stderr 并以非零状态退出。设计选择是：**宁可不跑，也别带着空基线跑**。

因为基线为空时，`on_packet` 里那句 `if claimed_ip not in baseline: return` 永远成立，每个包都被丢掉，检测器看起来在运行，实际什么也没做。这种**静默失效**比直接报错危险得多。

为什么要用全局字典而不是返回值：`on_packet` 是 `sniff` 的回调，scapy 规定它只接受一个 `pkt` 参数，没地方塞额外参数。全局变量是这里最省事的做法，代价是可测试性差、一个进程只能跑一个实例。

### on_packet()：三层过滤，顺序不能乱

**第一层，只放行应答：**

```python
if ARP not in pkt or pkt[ARP].op != 2:
    return
```

两个判断用 `or` 连起来，顺序有讲究：

- `ARP not in pkt` 必须在前，否则下一句 `pkt[ARP]` 会抛 KeyError。虽然 `sniff` 已经用 `filter="arp"` 过滤过，理论上不会出现非 ARP 包，但防御性写法在这里成本几乎为零
- `op != 2` —— 只处理 is-at。为什么不管请求（op=1）：正常主机的 who-has 里也带着自己的 MAC，但内核不会用请求去改缓存，处理它只会凭空制造误报

**第二层，取出「声称的身份」：**

```python
claimed_ip = pkt[ARP].psrc
claimed_mac = pkt[ARP].hwsrc
```

注意变量名里的 `claimed`（声称的）。**这两个值是「对方说的」，不是「事实」**。整个 ARP 欺骗就在这两个字段上撒谎，检测也就在这两个字段上找矛盾。

**第三层，只监控关心的主机：**

```python
if claimed_ip not in baseline:
    return
```

网段里其他机器的 ARP 应答怎么变都不归我们管。想让检测器盯多台主机，往 `baseline` 里多塞几条就行，代码一行不用改。

**比对：**

```python
known_mac = baseline[claimed_ip]
if claimed_mac.lower() == known_mac.lower():
    return
```

`lower()` 不能省。scapy 不同版本、不同系统返回的 MAC 大小写不一致，直接 `==` 会误报——这种坑不踩一次想不到。

**告警：**

```python
print(f"[!] {stamp()} ARP 欺骗告警：{claimed_ip} 声称 MAC 是 {claimed_mac}，"
      f"但基线是 {known_mac}", flush=True)
print(f"    来源帧：src MAC={pkt[Ether].src}  ->  如果你没换网卡，这就是攻击者", flush=True)
```

两个细节值得记：

- **`flush=True`**：`print` 默认带缓冲，输出重定向到文件时（实验 5 里的 `> /tmp/detect.log`）不 flush 的话日志可能迟迟不落盘，`cat` 出来是空的。和 tcpdump 要加 `-l` 是同一类问题
- **第二行打印的是 `pkt[Ether].src`，不是 `claimed_mac`**。这两个值含义不同：`hwsrc` 是「报文里声称的 MAC」，`Ether.src` 是「帧实际从哪块网卡发出」。正常情况下两者相同；水平高一点的攻击者可以让 `hwsrc` 和 `Ether.src` 对不上（伪造声称的 MAC，但帧头仍暴露自己）。抓帧头更接近「谁真的发了这个包」

### main()：sniff 的四个参数

```python
sniff(iface=args.iface, filter="arp", prn=on_packet, store=False)
```

- `iface="eth0"`：在哪块网卡上抓
- `filter="arp"`：**BPF 过滤器，在内核态就把非 ARP 的包扔掉**，根本不会送到 Python 层。这比在 `on_packet` 里判断 `if ARP not in pkt` 省得多——后者意味着每个包都要先从内核拷贝到用户态。用 `filter=` 需要 libpcap，镜像里装了 tcpdump 所以有
- `prn=on_packet`：每来一个包调用一次。注意如果 `prn` 的函数返回了值，scapy 会把返回值当包发出去；`on_packet` 里全是 `return` 和 `print`，没有返回值，安全
- `store=False`：**不把包存进列表**。默认 `store=True` 会把每个收到的包追加进内存，跑一天能吃掉几百 MB。检测器只需要「看一眼」，不需要「留底」

`sniff` 是阻塞的，Ctrl-C 直接退出。这里不需要 `try/except KeyboardInterrupt`——检测器退出时没有任何状态需要恢复（对比 `arpspoof.py` 必须 `restore()`，否则受害者断网）。

### 这套逻辑的盲区

- **合法变更会误报**：网关真换了网卡、或做了 VRRP 主备切换，MAC 确实会变
- **基线建立时机**：如果基线是在被毒化之后才建的，基线本身就是错的，之后所有正确映射反而会被当成异常。启动检测器前先确认网络是干净的
- **伪造得一模一样就检测不到**：攻击者把 MAC 伪造成和真网关完全相同，这套逻辑抓不到（但那样它也得真的接管那个 MAC 才有用）
- **看不到单向攻击**：如果攻击者只骗网关、不骗受害者，受害者侧什么异常也看不到

所以企业里的做法不是靠这个脚本，而是交换机上的 **DAI（动态 ARP 检测）**：配合 DHCP snooping 建立「IP-MAC-端口」绑定表，端口上收到的 ARP 如果和表对不上，直接在交换机层面丢弃。攻击包连受害者都到不了。

### 想拿它当工具用，还得补什么

- **持久化**：告警写文件或发 syslog，别只打在终端
- **白名单**：合法 MAC 变更要有例外机制，否则运维会被误报淹没
- **多目标**：往 `baseline` 里加条目，顺手把 `--watch` 改成 `nargs="+"`
- **定期重验**：基线放久了会过期，隔一段时间重新确认一次

`arpwatch` 走的是完全一样的思路（记录 IP-MAC 对，变化就告警），区别在于它是通用守护进程、靠 syslog 和邮件通知；自己写的好处是能精确控制监控对象，也能把这些细节摊开看。

## 十、server.py 存在的意义

严格说它不是攻击的一部分，但它解决了教学上的一个刚需：**怎么证明攻击真的成功**。

判断标准要靠两个证据同时成立：

- 攻击机抓到了明文密码 → 说明流量被引过来了
- 网关日志里也收到了同一个请求 → 说明包被转发出去了，不是断网

只有第一个不够：只能说明包到了攻击机，不能说明它还被转出去了（可能是断网 DoS，也可能是别的残留缓存把包引过来的）。只有第二个也不够：网关收到请求时，完全不知道链路中间多了一台机器。**两个都有，才是中间人。**

server.py 就是负责产生第二个证据的那一端——它把收到的 `user/pass` 原样打印出来，和攻击机抓到的一对照，链条就闭合了。

## 十一、几个常见疑问

**为什么我用 arpspoof 抓不到任何东西？**
先看 `ip neigh` 的状态。如果还是 `REACHABLE` 且 MAC 没变，就是还没到攻击窗口，等一会儿或者 `nud stale`。如果 MAC 变了但抓不到包，检查攻击机的 `ip_forward` 和 tcpdump 的 `-l`（缓冲问题）。

**HTTPS 能防住这个吗？**
能防「看到内容」，防不住「中间人存在」。攻击者仍然能拿到你访问了哪些域名、流量大小、时序；还能做 SSL 剥离（把 HTTPS 降级成 HTTP）、DNS 劫持。所以加密是必要但不充分的。

**交换机能不能自动防？**
普通交换机不能，它只按 MAC 转发。能防的是带 DAI / DHCP snooping 的可网管交换机，或者做了端口隔离的。

**为什么请求是广播、应答是单播，这个区别重要吗？**
重要，两个地方用到：一是攻击时选单播（隐蔽），二是检测时必须在受害者侧（第三方看不到单播）。
