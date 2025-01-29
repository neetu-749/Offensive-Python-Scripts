import socket

# Define target server details
TARGET_HOST = "127.0.0.1"  # Change this to the target IP if needed
TARGET_PORT = 1997         # Change this to the target port

# Create a UDP socket
client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

# Define the message to send
message = b"AAABBBCCC"

# Send data to the target server
client.sendto(message, (TARGET_HOST, TARGET_PORT))
print(f"Sent: {message.decode()} to {TARGET_HOST}:{TARGET_PORT}")

# Receive response from the server
data, server_address = client.recvfrom(4096)
print(f"Received: {data.decode()} from {server_address}")

# Close the socket
client.close()
