import ipaddress
import os
import socket
import struct
import sys

"""
# 📌 Purpose of This Script:
This script captures **raw IP packets**, extracts the IP header, and prints the **protocol, source, and destination IPs**.

# 🔹 Use Cases:
- Capturing and analyzing **IP headers**.
- Learning **network packet structure**.
- Understanding **protocols like ICMP, TCP, and UDP**.
- Performing **network security testing**.

⚠ **Note:** This script requires **administrative/root privileges** to access raw sockets.
"""

class IP:
    """
    This class represents an **IP header**.
    It extracts relevant fields from raw packet data and converts binary IP addresses to human-readable format.
    """
    def __init__(self, buff=None):
        # Unpack the first 20 bytes of the IP header
        header = struct.unpack('<BBHHHBBH4s4s', buff)

        self.ver = header[0] >> 4  # Extract IP version (IPv4 or IPv6)
        self.ihl = header[0] & 0xF  # Extract header length (in 32-bit words)
        self.tos = header[1]  # Type of Service (TOS)
        self.len = header[2]  # Total Length of the packet
        self.id = header[3]  # Identification field
        self.offset = header[4]  # Fragment Offset
        self.ttl = header[5]  # Time to Live (TTL)
        self.protocol_num = header[6]  # Protocol (TCP, UDP, ICMP, etc.)
        self.sum = header[7]  # Header checksum
        self.src = header[8]  # Source IP (binary)
        self.dst = header[9]  # Destination IP (binary)

        # Convert binary IP addresses to human-readable format
        self.src_address = ipaddress.ip_address(self.src)
        self.dst_address = ipaddress.ip_address(self.dst)

        # Map protocol constants to their names
        self.protocol_map = {1: "ICMP", 6: "TCP", 17: "UDP"}
        try:
            self.protocol = self.protocol_map[self.protocol_num]
        except KeyError:
            print('No protocol mapping for %s' % self.protocol_num)
            self.protocol = str(self.protocol_num)

def sniff(host):
    """
    This function sets up a **raw socket** to capture network packets.

    - Uses different settings for Windows and Linux.
    - Reads packets and extracts **IP header information**.
    - Prints the detected protocol and source/destination IPs.
    """

    # 📌 Select the correct socket protocol based on the OS
    if os.name == 'nt':  # Windows: Capture all incoming packets
        socket_protocol = socket.IPPROTO_IP
    else:  # Linux/macOS: Capture only ICMP packets
        socket_protocol = socket.IPPROTO_ICMP

    # 📌 Create a raw socket
    sniffer = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket_protocol)

    # 📌 Bind the sniffer to the **specified host IP** and port 0 (any available port)
    sniffer.bind((host, 0))

    # 📌 Include the **IP header** in captured packets
    sniffer.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

    # 📌 Enable promiscuous mode on Windows
    if os.name == 'nt':
        sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)

    try:
        while True:
            # 📌 Read a packet
            raw_buffer = sniffer.recvfrom(65535)[0]

            # 📌 Create an IP header from the first 20 bytes
            ip_header = IP(raw_buffer[0:20])

            # 📌 Print the detected protocol and source/destination IPs
            print('Protocol: %s %s -> %s' % (ip_header.protocol, ip_header.src_address, ip_header.dst_address))

    except KeyboardInterrupt:
        print("\n[!] Stopping Sniffer...")
        # 📌 Disable promiscuous mode on Windows before exiting
        if os.name == 'nt':
            sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
        sys.exit()

if __name__ == '__main__':
    """
    # 📌 How to Run This Script:
    
    # 🔹 On Windows (Run as Administrator):
    python ip_sniffer.py <YOUR_IP_HERE>

    # 🔹 On Linux/macOS (Run as Root):
    sudo python ip_sniffer.py <YOUR_IP_HERE>

    # 💡 Notes:
    - This script captures **raw IP headers** and extracts source/destination addresses.
    - It prints the **protocol** (ICMP, TCP, UDP) along with the **source and destination IPs**.
    - You **must run this script with admin/root privileges** to access raw sockets.
    - Replace `<YOUR_IP_HERE>` with your actual **local machine IP address**.
    """

    if len(sys.argv) == 2:
        host = sys.argv[1]
    else:
        host = 'YOUR_IP_HERE'  # Replace with actual IP
    sniff(host)
