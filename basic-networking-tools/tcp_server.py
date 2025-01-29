import socket
import threading

# Define the server IP and Port
IP = "0.0.0.0"  # Listen on all available interfaces
PORT = 9998     # Define the port number for incoming connections

def main():
    # Create a TCP socket
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    
    # Bind the socket to the specified IP and port
    server.bind((IP, PORT))

    # Start listening with a backlog of 5 connections
    server.listen(5)
    print(f"[*] Listening on {IP}:{PORT}")

    # Server waits for incoming connections
    while True:
        client, address = server.accept()  # Accept new client connection
        print(f"[*] Accepted connection from {address[0]}:{address[1]}")

        # Create a new thread to handle the client
        client_handler = threading.Thread(target=handle_client, args=(client,))
        client_handler.start()  # Start the thread

def handle_client(client_socket):
    """Handles communication with a connected client"""
    with client_socket as sock:
        # Receive data from client
        request = sock.recv(1024)
        print(f"[*] Received: {request.decode('utf-8')}")

        # Send acknowledgment back to the client
        sock.send(b"ACK")

# Ensure the script runs only when executed directly
if __name__ == "__main__":
    main()
