import socket
from collections import defaultdict

import dpkt

# Ports used by the protocols we are interested in
# Source: https://en.wikipedia.org/wiki/List_of_TCP_and_UDP_port_numbers
PORT_HTTP = 80
PORT_HTTPS = 443
PORT_FTP_DATA = 20
PORT_FTP_CONTROL = 21
PORT_SSH = 22
PORT_SMTP = 25
PORT_DHCP_1 = 67
PORT_DHCP_2 = 68
PORT_NTP = 123


# Constants for detecting SYN scanning
SYN_SENT_MINIMUM = 50
SYN_RECEIVED_MULTIPLIER = 3


def packet_summary(filename: str):
    """Prints hierarchically by type the number of packets seen."""
    # Initialize counters
    ethernet_count = ip_count = tcp_count = http_count = https_count = ftp_count = ssh_count = smtp_count = udp_count = dhcp_count = ntp_count = non_ip_count = arp_count = 0
    dns_count = 0
    # Open the pcap file
    with open(filename, 'rb') as file:
        # Create a pcap reader
        pcap_reader = dpkt.pcap.Reader(file)

        # Iterate through each packet in the pcap file
        for timestamp, buf in pcap_reader:
            try:
                # Parse the Ethernet frame
                eth = dpkt.ethernet.Ethernet(buf)
                ethernet_count += 1

                # Check if it's an IPv4 or IPv6 packet
                if isinstance(eth.data, dpkt.ip.IP):
                    ip_count += 1
                    if eth.data.p == dpkt.ip.IP_PROTO_TCP:
                        tcp_count += 1
                        tcp_src_port = eth.data.data.sport
                        tcp_dst_port = eth.data.data.dport
                        # Check for specific protocols based on ports
                        if tcp_src_port == PORT_HTTP or tcp_dst_port == PORT_HTTP:
                            http_count += 1
                        elif tcp_src_port == PORT_HTTPS or tcp_dst_port == PORT_HTTPS:
                            https_count += 1
                        elif tcp_src_port == PORT_FTP_CONTROL or tcp_dst_port == PORT_FTP_CONTROL:
                            ftp_count += 1
                        elif tcp_src_port == PORT_SSH or tcp_dst_port == PORT_SSH:
                            ssh_count += 1
                        elif tcp_src_port == PORT_SMTP or tcp_dst_port == PORT_SMTP:
                            smtp_count += 1
                    elif eth.data.p == dpkt.ip.IP_PROTO_UDP:
                        udp_count += 1
                        udp_src_port = eth.data.data.sport
                        udp_dst_port = eth.data.data.dport
                        # Check for specific protocols based on ports
                        if udp_src_port == PORT_DHCP_1 or udp_dst_port == PORT_DHCP_1 or udp_src_port == PORT_DHCP_2 or udp_dst_port == PORT_DHCP_2:
                            dhcp_count += 1
                        elif udp_src_port == PORT_NTP or udp_dst_port == PORT_NTP:
                            ntp_count += 1
                        elif udp_dst_port == 53 or udp_src_port == 53:
                            # add this to result below
                            dns_count += 1
                        else:
                            pass
                            #port 137 and 1900
                            # tmp_port_source = udp_dst_port
                            # tmp_port_dest = udp_src_port 
                            # print("uncaught ports: " + str(tmp_port_source) +" and "+ str(tmp_port_dest))
                    else:
                        # Other IP protocols
                        non_ip_count += 1

                    # Check if it's IPv4 or IPv6
                    if isinstance(eth.data, dpkt.ip.IP):
                        if eth.data.v == 6:
                            pass
                            #ip_count += 1

                elif isinstance(eth.data, dpkt.arp.ARP):
                    non_ip_count += 1
                    arp_count += 1
                else:
                    non_ip_count += 1
            except Exception as e:
                # Handle any exceptions that may occur during packet parsing
                print(f"Error parsing packet: {e}")

    # Print the summary
    print("Packet Summary:")
    print(f"Ethernet: {ethernet_count}")
    print(f"\tIP: {ip_count}")
    print(f"\t\tTCP: {tcp_count}")
    print(f"\t\t\tHTTP: {http_count}")
    print(f"\t\t\tHTTPS: {https_count}")
    print(f"\t\t\tFTP: {ftp_count}")
    print(f"\t\t\tSSH: {ssh_count}")
    print(f"\t\t\tSMTP: {smtp_count}")
    print(f"\t\tUDP: {udp_count}")
    print(f"\t\t\tDHCP: {dhcp_count}")
    print(f"\t\t\tNTP: {ntp_count}")
    print(f"\tNon-IP: {non_ip_count}")
    print(f"\t\tARP: {arp_count}")
    print(f'DNS: {dns_count}')


def subnet_summary(filename: str):
    """Prints the different subnets appearing in the packets."""
    subnets = defaultdict(lambda: 0)
    with open(filename, 'rb') as file:
        # Create a pcap reader
        pcap_reader = dpkt.pcap.Reader(file)

        # Iterate through each packet in the pcap file
        for timestamp, buf in pcap_reader:
            eth = dpkt.ethernet.Ethernet(buf)
            if isinstance(eth.data, dpkt.ip.IP) and eth.data.v == 4:
                source_addr = socket.inet_ntoa(eth.data.src)
                dest_addr = socket.inet_ntoa(eth.data.dst)
                source_subnet = source_addr[:source_addr.find(".", source_addr.find(".") + 1)]
                dest_subnet = dest_addr[:dest_addr.find(".", dest_addr.find(".") + 1)]
                subnets[source_subnet]+=1
                subnets[dest_subnet]+=1
        print("Subnet Summary:")
        subnets = sorted(subnets.items(), key= lambda x: x[1], reverse=True)
        for subnet in subnets:
            print(f'{subnet[0]}\t{subnet[1]}')




def detect_syn_scanning(filename: str):
    """Prints IP addresses that potentially performed SYN scans."""
    # significantly more means 3 times the amount sent than received and difference is at least 50
    syn_scanners = defaultdict(lambda: [0,0])
    with open(filename, 'rb') as file:
        # Create a pcap reader
        pcap_reader = dpkt.pcap.Reader(file)

        # Iterate through each packet in the pcap file
        for timestamp, buf in pcap_reader:
            eth = dpkt.ethernet.Ethernet(buf)
            if isinstance(eth.data, dpkt.ip.IP):
                    if isinstance(eth.data.data, dpkt.tcp.TCP):
                        source_addr = socket.inet_ntoa(eth.data.src)
                        tcp_packet = eth.data.data
                        flag = tcp_packet.flags
                        if (flag & dpkt.tcp.TH_SYN) != 0:
                            if (flag & dpkt.tcp.TH_ACK) != 0:
                                syn_scanners[source_addr][1] +=1
                            else:
                                syn_scanners[source_addr][0] +=1
        print("SYN Scanners (sent, received):")
        for ip in syn_scanners:
            if (syn_scanners[ip][0] > 3*syn_scanners[ip][1] and (syn_scanners[ip][0] - syn_scanners[ip][1]) >= 50):
                print(f'{ip} ({syn_scanners[ip][0]},{syn_scanners[ip][1]})')




if __name__ == "__main__":
    packet_summary("part1.pcap")
    subnet_summary("part1.pcap")
    detect_syn_scanning("part2.pcap")
