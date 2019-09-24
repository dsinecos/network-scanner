import scapy.all as scapy

def scan(ip):
    # Create an ARP Request to fetch the MAC Addr for 'ip' provided as pdst
    arp_request = scapy.ARP(pdst=ip)
    # Log ARP Packet's summary
    print(arp_request.summary())
    # Log ARP Packet's contents
    # To print for a Range of IPs '10.0.2.1/24'
    # for element in arp_request:
    #     print(element.show())
    # To print for a single IP '10.0.2.2'
    # print(arp_request.show())

    # Create an Ethernet Frame
    broadcast_req = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    # Log Ethernet frame's summary
    print(broadcast_req.summary())
    # Log Ethernet frame's contents
    print(broadcast_req.show())

    # Combine the ARP Request packet and the Ethernet frame
    arp_request_broadcast = broadcast_req/arp_request
    # Log summary of the combined frame
    print(arp_request_broadcast.summary())
    # Log contents of the combined frame
    # To print for a Range of IPs '10.0.2.1/24'
    # for element in arp_request_broadcast:
    #     print(element.show())
    # To print for a single IP '10.0.2.2'
    # print(arp_request_broadcast.show())

    # Send packet
    ans, unans = scapy.srp(arp_request_broadcast, timeout=2, verbose=False)
    # ans contains a list of all request packets and corresponding response packets
    print(ans.summary())
    # unans contains a list of all request packets that did not receive a response
    print(unans.summary())

    ip_mac_list = []

    for element in ans:
        print("Inside Loop")
        # print(element)
        response_pkt = element[1]
        print(response_pkt.show())
        print(response_pkt.psrc)
        print(response_pkt.hwsrc)
        print(response_pkt.src)
        ip_mac_list.append({
            "ip": response_pkt.psrc,
            "mac": response_pkt.hwsrc
        })
    
    return ip_mac_list

    # Make an ARP Request to get the MAC Addr for 'ip'
    # scapy.arping(ip)

def print_ip_mac_list(ip_mac_list):
    print("IP Addr \t\t\t MAC Addr")
    for element in ip_mac_list:
        print(element["ip"] + "\t\t\t" + element["mac"])

# print_ip_mac_list(scan("10.0.2.2"))

print_ip_mac_list(scan("10.0.2.1/24"))
# scapy.arping("10.0.2.1/24")