import socket

# Define target server details
TARGET_HOST = "127.0.0.1"  # Change this to the server's IP address
TARGET_PORT = 9998         # Change this to the desired port

# Create a TCP socket
client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

try:
    # Connect to the target server
    client.connect((TARGET_HOST, TARGET_PORT))
    print(f"Connected to {TARGET_HOST}:{TARGET_PORT}")

    # Send a message to the server
    MESSAGE = b"Hello, Server!"  # Modify this message as needed
    client.send(MESSAGE)
    print("Message sent to server.")

    # Receive response from the server
    response = client.recv(4096)  # 4KB buffer size
    print("Received response from server:")
    print(response.decode())

except Exception as e:
    print(f"Error: {e}")

finally:
    # Close the socket connection
    client.close()
    print("Connection closed.")
