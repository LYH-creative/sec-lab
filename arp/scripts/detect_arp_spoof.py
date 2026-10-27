#!/usr/bin/env python3
"""
ARP 欺骗检测 —— 跑在「受害者」这一侧

为什么检测要放在受害者上？
  攻击机发的是「单播」ARP 应答（Ether.dst 直接写受害者 MAC），
  同网段第三台机器在交换机上根本收不到这些包，所以传统的
  「旁路 arpwatch」在这个场景里是瞎的。
  真正能看到谎言的，只有被骗的那台主机的网卡。

检测逻辑（这就是绝大多数 ARP IDS 的核心思路）：
  1. 记住某台关键主机（这里是网关）的 IP -> MAC 映射
  2. 之后每收到一个 ARP is-at 应答，看它声称的 MAC 是否变了
  3. 变了就告警 —— 因为正常情况下网关的 MAC 不可能说变就变

局限（必须知道，否则会误判）：
  - 网关真的换了网卡 / 做了 VRRP 主备切换，也会触发告警
  - 攻击者如果伪造得跟真 MAC 一模一样，这套逻辑抓不到

用法：
  python3 detect_arp_spoof.py                    # 监控默认网关 172.28.0.2
  python3 detect_arp_spoof.py --watch 172.28.0.2 --iface eth0
"""

import argparse
import sys
from datetime import datetime

from scapy.all import ARP, Ether, sniff, srp

# ip -> mac 的「已知正确」基线
baseline = {}


def stamp():
    return datetime.now().strftime("%H:%M:%S")


def build_baseline(watch_ip, iface):
    """
    开局先正常问一次，建立基线。
    这一步很关键：如果开机就先被毒化了，基线本身就是错的，
    检测器会把「正确的」当成「异常的」。
    生产环境的做法是靠配置文件 / DHCP snooping 表来钉死基线。
    """
    ans, _ = srp(
        Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=watch_ip),
        iface=iface,
        timeout=2,
        verbose=False,
    )
    for _, rcv in ans:
        mac = rcv[ARP].hwsrc
        baseline[watch_ip] = mac
        print(f"[*] 基线：{watch_ip} -> {mac}")
        return
    sys.exit(f"[!] 建立基线失败：{watch_ip} 没有回应 ARP")


def on_packet(pkt):
    # 只关心 ARP 应答（is-at）。请求（who-has）里也带发送者信息，
    # 但正常主机不会用请求去改别人的缓存，这里先不处理
    if ARP not in pkt or pkt[ARP].op != 2:
        return

    claimed_ip = pkt[ARP].psrc
    claimed_mac = pkt[ARP].hwsrc

    if claimed_ip not in baseline:
        return

    known_mac = baseline[claimed_ip]
    if claimed_mac.lower() == known_mac.lower():
        return

    # 关键告警：有人正在声称自己是那台主机
    print(
        f"[!] {stamp()} ARP 欺骗告警：{claimed_ip} 声称 MAC 是 {claimed_mac}，"
        f"但基线是 {known_mac}",
        flush=True,
    )
    print(
        f"    来源帧：src MAC={pkt[Ether].src}  ->  如果你没换网卡，这就是攻击者",
        flush=True,
    )


def main():
    p = argparse.ArgumentParser(description="ARP 欺骗检测（受害者侧）")
    p.add_argument("--watch", default="172.28.0.2", help="要保护的主机 IP（默认网关）")
    p.add_argument("-i", "--iface", default="eth0")
    args = p.parse_args()

    build_baseline(args.watch, args.iface)
    print("[*] 开始监听 ARP 应答，Ctrl-C 停止")
    # store=False：不把包堆在内存里，长时间跑也不会吃满
    sniff(iface=args.iface, filter="arp", prn=on_packet, store=False)


if __name__ == "__main__":
    main()
