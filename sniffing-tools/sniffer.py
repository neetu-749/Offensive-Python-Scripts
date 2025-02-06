import socket
import os

# 📌 Define the host to listen on (Replace with your machine's IP)
HOST = 'Your_Host_address_here'

def main():
    """
    Sets up a raw socket sniffer to capture packets.
    
    - Uses different settings for Windows and Linux.
    - Enables promiscuous mode on Windows.
    - Captures and prints a single packet.
    """

    # Determine the correct socket protocol based on OS
    if os.name == 'nt':  # Windows: Capture all incoming packets
        socket_protocol = socket.IPPROTO_IP
    else:  # Linux/macOS: Capture only ICMP packets
        socket_protocol = socket.IPPROTO_ICMP

    # Create a raw socket
    sniffer = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket_protocol)

    # Bind the sniffer to the host machine's IP address
    sniffer.bind((HOST, 0))

    # Include the IP header in the captured packets
    sniffer.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

    # Enable promiscuous mode on Windows
    if os.name == 'nt':
        sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)

    # Capture a single packet
    print("[*] Sniffing started... Waiting for a packet")
    packet = sniffer.recvfrom(65565)  # Receive a packet
    print("[*] Packet Captured:\n", packet)

    # Disable promiscuous mode on Windows before exiting
    if os.name == 'nt':
        sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)

if __name__ == '__main__':
    main()

"""
# 📌 Purpose of This Script:
This script is a basic packet sniffer that captures raw network packets using raw sockets.

# 🔹 Use Cases:
- Capturing network traffic for analysis.
- Understanding how raw sockets work.
- Learning network security and penetration testing.
- Debugging incoming network packets.

# 📌 How to Run This Script:

# 🔹 On Windows (Run as Administrator):
python sniffer.py

# 🔹 On Linux (Run as Root):
sudo python sniffer.py

# 💡 Notes:
- On **Windows**, the script captures **all packets** by enabling promiscuous mode.
- On **Linux**, it captures **only ICMP packets** unless modified.
- You **must run this script with admin/root privileges** to access raw sockets.
"""
