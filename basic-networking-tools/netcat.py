import argparse
import socket
import ssl
import shlex
import subprocess
import sys
import textwrap
import threading

"""
NetCat Tool - A Python implementation of the popular netcat utility.
---------------------------------------------------------
Functionality:
This tool is designed for secure network communication, providing features like:
1. Listening on a port to accept incoming connections.
2. Sending data to a remote target.
3. Executing system commands on the listener side.
4. Uploading files securely.
5. Opening a command shell for interactive communication.

Key Features:
- SSL Encryption: Secures communication using user-provided certificates.
- Multithreading: Handles multiple connections simultaneously.
- Customizable: Allows users to upload files, execute commands, or run a command shell.

Usage Examples:
1. Start a listener on port 5555 with a command shell:
   python netcat.py -t 127.0.0.1 -p 5555 -l -c

2. Upload a file to the listener:
   python netcat.py -t 127.0.0.1 -p 5555 -l -u myfile.txt

3. Execute a command on the listener:
   python netcat.py -t 127.0.0.1 -p 5555 -l -e "ls -la"

4. Send data to a remote listener:
   echo "Hello, World!" | python netcat.py -t 127.0.0.1 -p 5555

Note:
- Replace `Your_cert.pem` and `Your_key.pem` with your SSL certificate and key files.
- Always use this tool responsibly and with permission.
"""

# Function to execute shell commands
def execute(cmd):
    """
    Executes a shell command and returns the output.
    Args:
        cmd (str): Command to execute.
    Returns:
        str: Command output.
    """
    cmd = cmd.strip()
    if not cmd:
        return
    output = subprocess.check_output(shlex.split(cmd), stderr=subprocess.STDOUT)
    return output.decode()


class NetCat:
    def __init__(self, args, buffer=None):
        """
        Initializes the NetCat object.
        Args:
            args (Namespace): Parsed command-line arguments.
            buffer (bytes): Data to send when connecting to a target.
        """
        self.args = args
        self.buffer = buffer
        # Create a secure SSL socket
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.socket = ssl.wrap_socket(
            self.socket, certfile="Your_cert.pem", keyfile="Your_key.pem", server_side=self.args.listen
        )

    def run(self):
        """
        Starts the NetCat tool in either listen or send mode.
        """
        if self.args.listen:
            self.listen()
        else:
            self.send()

    def send(self):
        """
        Connects to a remote target and facilitates communication.
        """
        self.socket.connect((self.args.target, self.args.port))
        if self.buffer:
            self.socket.send(self.buffer)
        try:
            while True:
                recv_len = 1
                response = ''
                while recv_len:
                    data = self.socket.recv(4096)
                    recv_len = len(data)
                    response += data.decode()
                    if recv_len < 4096:
                        break
                if response:
                    print(response)
                    buffer = input("> ")  # Accept user input
                    buffer += "\n"
                    self.socket.send(buffer.encode())
        except KeyboardInterrupt:
            print("User terminated the connection.")
            self.socket.close()
            sys.exit()

    def listen(self):
        """
        Listens for incoming connections and starts a new thread for each client.
        """
        self.socket.bind((self.args.target, self.args.port))
        self.socket.listen(5)
        print(f"[*] Listening on {self.args.target}:{self.args.port}")
        while True:
            client_socket, _ = self.socket.accept()
            # Start a new thread to handle the client
            client_thread = threading.Thread(target=self.handle, args=(client_socket,))
            client_thread.start()

    def handle(self, client_socket):
        """
        Handles a client connection based on the specified mode (upload, execute, or command shell).
        Args:
            client_socket (socket): The client socket.
        """
        if self.args.execute:
            # Execute a specified command and send the output
            output = execute(self.args.execute)
            client_socket.send(output.encode())

        elif self.args.upload:
            # Receive a file from the client and save it
            file_buffer = b""
            while True:
                data = client_socket.recv(4096)
                if data:
                    file_buffer += data
                else:
                    break
            with open(self.args.upload, "wb") as f:
                f.write(file_buffer)
            message = f"Saved file {self.args.upload}"
            client_socket.send(message.encode())

        elif self.args.command:
            # Start a command shell for interactive input
            cmd_buffer = b""
            while True:
                try:
                    client_socket.send(b"NETCAT: #> ")
                    while "\n" not in cmd_buffer.decode():
                        cmd_buffer += client_socket.recv(64)
                    response = execute(cmd_buffer.decode())
                    if response:
                        client_socket.send(response.encode())
                    cmd_buffer = b""
                except Exception as e:
                    print(f"Server killed: {e}")
                    self.socket.close()
                    sys.exit()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Netcat tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent(
            """
            Example usage:
            (1) Listen on a port with a command shell:
            python netcat.py -t 127.0.0.1 -p 5555 -l -c
            
            (2) Upload a file to a listener:
            python netcat.py -t 127.0.0.1 -p 5555 -l -u=myfile.txt

            (3) Execute a command on a listener:
            python netcat.py -t 127.0.0.1 -p 5555 -l -e "ls -la"

            (4) Connect to a listener and send data:
            echo "Hello" | python netcat.py -t 127.0.0.1 -p 5555
            """
        ),
    )
    parser.add_argument("-c", "--command", action="store_true", help="Open a command shell")
    parser.add_argument("-e", "--execute", help="Execute a specified command")
    parser.add_argument("-l", "--listen", action="store_true", help="Listen for incoming connections")
    parser.add_argument("-p", "--port", type=int, default=5555, help="Target port")
    parser.add_argument("-t", "--target", default="127.0.0.1", help="Target IP address")
    parser.add_argument("-u", "--upload", help="Upload a file to the specified destination")

    args = parser.parse_args()
    if args.listen:
        buffer = b""
    else:
        buffer = sys.stdin.read().encode()

    nc = NetCat(args, buffer)
    nc.run()
