#! /usr/bin/env python3

import scapy.all as scapy
import click

def scan(ip):
    # Create an ARP Request to fetch the MAC Addr for 'ip' provided as pdst
    arp_request = scapy.ARP(pdst=ip)
    
    # Create an Ethernet Frame set to broadcast MAC Addr
    broadcast_req = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    
    # Combine the ARP Request packet and the Ethernet frame
    arp_request_broadcast = broadcast_req/arp_request

    # Send packet
    ans, unans = scapy.srp(arp_request_broadcast, timeout=2, verbose=False)
    ip_mac_list = []
    for element in ans:
        response_pkt = element[1]
        ip_mac_list.append({
            "ip": response_pkt.psrc,
            "mac": response_pkt.hwsrc
        })
    
    return ip_mac_list

def print_ip_mac_list(ip_mac_list):
    print("IP Addr \t\t\t MAC Addr")
    for element in ip_mac_list:
        print(element["ip"] + "\t\t\t" + element["mac"])

@click.command()
@click.option('--ip', '-i',
              help="Specify the IP Addr or IP Addr range to scan for MAC Addresses")
def main(ip):
    """
    CLI Tool to fetch the MAC Addr for an IP or a range of IPs within a subnet
    """
    print_ip_mac_list(scan(ip))

if __name__ == "__main__":
    main()  # pylint: disable=no-value-for-parameter

