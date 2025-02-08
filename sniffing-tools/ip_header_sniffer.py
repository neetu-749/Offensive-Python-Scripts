import ipaddress
import os
import socket
import struct 
import sys


"""
# 📌 Purpose of This Script:
This script is a **basic IP header sniffer** that captures raw **IP packets** using **raw sockets**.
It listens on a network interface, captures packets, and prints their raw data.

# 🔹 Use Cases:
- Capturing and analyzing **IP headers**.
- Learning **how raw sockets work** in networking.
- Understanding **network protocols and packet structures**.
- Performing basic **network security testing**.

⚠ **Note:** This script requires **administrative/root privileges** to access raw sockets.
"""

# 📌 Define the host to listen on (Replace with your actual machine's IP)
HOST = 'YOUR_HOST_IP_HERE'  # Example: '192.168.1.100'

def main():
    """
    Sets up a raw socket sniffer to capture **IP headers**.

    - Uses different settings for Windows and Linux.
    - Enables **promiscuous mode** on Windows.
    - Captures and prints **a single IP packet**.
    """

    # 📌 Select the correct socket protocol based on the OS
    if os.name == 'nt':  # Windows: Capture all incoming packets
        socket_protocol = socket.IPPROTO_IP
    else:  # Linux/macOS: Capture only ICMP packets
        socket_protocol = socket.IPPROTO_ICMP

    # 📌 Create a raw socket to capture **IP packets**
    sniffer = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket_protocol)

    # 📌 Bind the sniffer to the **specified host IP** and port 0 (any available port)
    sniffer.bind((HOST, 0))

    # 📌 Include the **IP header** in captured packets
    sniffer.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

    # 📌 Enable promiscuous mode on Windows to capture all network traffic
    if os.name == 'nt':
        sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)

    # 📌 Capture a **single IP packet**
    print("[*] Sniffing started... Waiting for an IP packet")
    packet = sniffer.recvfrom(65565)  # Receive a packet (max size: 65,565 bytes)
    print("[*] IP Packet Captured:\n", packet)

    # 📌 Disable promiscuous mode on Windows before exiting
    if os.name == 'nt':
        sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)

if __name__ == '__main__':
    main()

"""
# 📌 How to Run This Script:

# 🔹 On Windows (Run as Administrator):
python ip_header_sniffer.py

# 🔹 On Linux/macOS (Run as Root):
sudo python ip_header_sniffer.py

# 💡 Notes:
- This script captures **only IP headers**, not full packet payloads.
- On **Windows**, it captures **all IP packets**.
- On **Linux**, it captures **only ICMP packets** unless modified.
- You **must run this script with admin/root privileges** to access raw sockets.
- Replace `"YOUR_HOST_IP_HERE"` with your actual **local machine IP address**.
"""
