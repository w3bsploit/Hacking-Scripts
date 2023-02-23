#Scans your network & returns a list of IP addresses & their MAC Address association.
#Currently only compatible with Linux
#!/usr/bin/env python

import scapy.all as scapy
import optparse
def get_ip():
    parser = optparse.OptionParser()
    parser.add_option("-t", "--target", dest="target", help="Enter target IP / range here")

    (options, arguments) = parser.parse_args()

    if not options.target:
      parser.error("[-] Please specify a valid IP address, use --help for more information")
    return options
def scan(ip):
    #init arp packet
    arp_request = scapy.ARP(pdst=ip)
    #arp_request.show()

    #send request packet to broadcast mac address
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    #broadcast.show()
    scapy.ls(scapy.Ether())


    #combine both packets to create a frame
    arp_request_broadcast = broadcast/arp_request

    #wait for response of request, split into two variables (answered who has IP & those who ignored the packet)
    answered_list, unanswered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]


    clients_list = {}
    for element in answered_list:
        client_dict = {"ip":element[1].psrc, "mac": element[1].hwsrc}
        clients_list.append(client_dict)
    return clients_list


    #arp_request_broadcast.show()
    #print(broadcast.summary())

    #print(arp_request.summary())
    #scapy.ls(scapy.ARP())

def print_result(results_list):
    print("IP\t\t\tMAC Address\n-------------------------------------------------")
    for client in results_list:
        print(client["ip"] + "\t\t" + client["mac"])

options = get_ip()
scan_result = scan(options.target)
print_result(scan_result)
