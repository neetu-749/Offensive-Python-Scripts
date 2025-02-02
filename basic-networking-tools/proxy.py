import sys
import socket
import threading

# HEXFILTER converts bytes into printable ASCII characters or a dot (.) if not printable
HEX_FILTER = ''.join(
    [(len(repr(chr(i))) == 3) and chr(i) or '.' for i in range(256)]
)

def hexdump(src, length=16, show=True):
    """
    Prints a hex dump of the given data.
    
    Args:
        src (bytes): Data to be displayed in hex format.
        length (int): Number of bytes per line.
        show (bool): If True, prints output. Otherwise, returns results.

    Returns:
        list: Hexdump representation if show=False.
    """
    if isinstance(src, bytes):
        src = src.decode(errors='replace')  # Replace errors if decoding fails
    results = []
    for i in range(0, len(src), length):
        word = str(src[i:i+length])
        printable = word.translate(HEX_FILTER)  # Convert non-printable characters
        hexa = ' '.join([f'{ord(c):02X}' for c in word])
        hexwidth = length * 3
        results.append(f'{i:04x} {hexa:<{hexwidth}} {printable}')
    
    if show:
        for line in results:
            print(line)
    else:
        return results

def receive_from(connection):
    """
    Receives data from a socket with a 5-second timeout.

    Args:
        connection (socket): The socket to receive data from.

    Returns:
        bytes: The received data.
    """
    buffer = b""
    connection.settimeout(5)
    try:
        while True:
            data = connection.recv(4096)
            if not data:
                break
            buffer += data
    except Exception as e:
        pass
    return buffer

def request_handler(buffer):
    """
    Modify requests before forwarding them to the remote server.
    This function can be customized to modify HTTP headers, inject payloads, etc.

    Args:
        buffer (bytes): The original request data.

    Returns:
        bytes: The modified request data.
    """
    return buffer

def response_handler(buffer):
    """
    Modify responses before sending them back to the client.

    Args:
        buffer (bytes): The original response data.

    Returns:
        bytes: The modified response data.
    """
    return buffer

def proxy_handler(client_socket, remote_host, remote_port, receive_first):
    """
    Handles communication between the client and remote server.

    Args:
        client_socket (socket): The client connection.
        remote_host (str): The remote server's IP.
        remote_port (int): The remote server's port.
        receive_first (bool): Whether to receive data from the remote server first.
    """
    remote_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    remote_socket.connect((remote_host, remote_port))

    if receive_first:
        remote_buffer = receive_from(remote_socket)
        hexdump(remote_buffer)

        remote_buffer = response_handler(remote_buffer)
        if len(remote_buffer):
            print(f"[<==] Sending {len(remote_buffer)} bytes to localhost.")
            client_socket.send(remote_buffer)

    while True:
        # Receive data from client
        local_buffer = receive_from(client_socket)
        if len(local_buffer):
            print(f"[==>] Received {len(local_buffer)} bytes from localhost.")
            hexdump(local_buffer)

            local_buffer = request_handler(local_buffer)
            remote_socket.send(local_buffer)
            print("[==>] Sent to remote.")

        # Receive data from remote server
        remote_buffer = receive_from(remote_socket)
        if len(remote_buffer):
            print(f"[<==] Received {len(remote_buffer)} bytes from remote.")
            hexdump(remote_buffer)

            remote_buffer = response_handler(remote_buffer)
            client_socket.send(remote_buffer)
            print("[<==] Sent to localhost.")

        # If no data is received, close the connections
        if not len(local_buffer) or not len(remote_buffer):
            client_socket.close()
            remote_socket.close()
            print("[*] No more data. Closing connections.")
            break

def server_loop(local_host, local_port, remote_host, remote_port, receive_first):
    """
    Starts the proxy server and listens for incoming connections.

    Args:
        local_host (str): IP to bind the server to.
        local_port (int): Port to listen on.
        remote_host (str): Remote server to forward data to.
        remote_port (int): Remote port.
        receive_first (bool): Whether to receive data from the remote server first.
    """
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        server.bind((local_host, local_port))
    except Exception as e:
        print(f"Problem binding: {e}")
        print("[!!] Failed to listen. Check for other listening sockets or permissions.")
        sys.exit(0)

    print(f"[*] Listening on {local_host}:{local_port}")
    server.listen(5)

    while True:
        client_socket, addr = server.accept()
        print(f"> Received incoming connection from {addr[0]}:{addr[1]}")

        proxy_thread = threading.Thread(
            target=proxy_handler,
            args=(client_socket, remote_host, remote_port, receive_first)
        )
        proxy_thread.start()

def main():
    """
    Main function to parse command-line arguments and start the proxy.
    """
    if len(sys.argv[1:]) != 5:
        print("Usage: python proxy.py [localhost] [localport] [remotehost] [remoteport] [receive_first]")
        print("Example: python proxy.py 127.0.0.1 9000 10.12.132.1 9000 True")
        sys.exit(0)

    local_host = sys.argv[1]
    local_port = int(sys.argv[2])
    remote_host = sys.argv[3]
    remote_port = int(sys.argv[4])
    receive_first = sys.argv[5].lower() == "true"

    server_loop(local_host, local_port, remote_host, remote_port, receive_first)

if __name__ == "__main__":
    main()
