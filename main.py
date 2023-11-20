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
    pass


def subnet_summary(filename: str):
    """Prints the different subnets appearing in the packets."""
    pass


def detect_syn_scanning(filename: str):
    """Prints IP addresses that potentially performed SYN scans."""
    pass


if __name__ == "__main__":
    packet_summary("part1.pcap")
    subnet_summary("part1.pcap")
    detect_syn_scanning("part2.pcap")
