import argparse
import socket
import shlex
import subprocess
import sys
import textwrap
import threading

# set up the execution function
# this function will receive a command, run it and will return output as string
def execute(cmd):
    cmd = cmd.strip()
    if not cmd:
        return
    output = subprocess.check_output(shlex.split(cmd), stderr = subprocess.STDOUT)
    return output.decode()

class NetCat:
    #initialise netcat object with arguments from command line
    def __init__(self, args, buffer = None):
        self.args = args
        self.buffer = buffer
        #create a socket object
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    #run the entry point for managing netcat object
    def run(self):
        # if setting up a listner we call listen method else call send method
        if self.args.listen:
            self.listen()
        else:
            self.send()
        
    # send method
    def send(self):
        #connect to target port
        self.socket.connect((self.args.target, self.args.port))
        # if we have buffer send that to the target first
        if self.buffer:
            self.socket.send(self.buffer)
            # set up try/catch block so we can manually close the connection with CTRL+C
        try:
            #loop to receive data from target
            while True:
                recv_len = 1
                response = ''
                while recv_len:
                    data = self.socket.recv(4096)
                    recv_len = len(data)
                    response += data.decode()
                    #if there is no more data, break the loop
                    if recv_len < 4096:
                        break
                if response:
                    print(response)
                    buffer = input('> ')
                    buffer += '\n'
                    self.socket.send(buffer.encode()) #send the input from above response and continue the loop
        except KeyboardInterrupt:
            print('User terminated.')
            self.socket.close()
            sys.exit()

    # method that executes when the program runs as a listner:
    def listen(self):
        self.socket.bind((self.args.target, self.args.port))
        self.socket.listen(5)
        while True:
            client_socket, _ = self.socket.accept()
            client_thread = threading.Thread(
                target = self.handle, args = (client_socket,)
            )
            client_thread.start()
    
    # implementation of logic to perform file uploads, execute commands, and create interactive shell
    def handle(self, client_socket):
        if self.args.execute:
            output = execute(self.args.execute)
            client_socket.send(output.encode())
        
        elif self.args.upload:
            file_buffer = b''
            while True:
                data = client_socket.recv(4096)
                if data:
                    file_buffer += data
                else:
                    break
            with open(self.args.upload, 'wb') as f:
                f.write(file_buffer)
            message = f'Saved file {self.args.upload}'
            client_socket.send(message.encode())

        elif self.args.command:
            cmd_buffer = b''
            while True:
                try:
                    client_socket.send(b'NETCAT: #> ')
                    while '\n' not in cmd_buffer.decode():
                        cmd_buffer += client_socket.recv(64)
                    response = execute(cmd_buffer.decode())
                    if response:
                        client_socket.send(response.encode())
                    cmd_buffer = b''
                except Exception as e:
                    print(f'server killed {e}')
                    sys.exit()

# here we are using check_output method, which runs a command on local OS and then return output from that command
# main block responsible for handling command line arguments and calling rest of the functions
if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description = 'Netcat tool',
        formatter_class = argparse.RawDescriptionHelpFormatter,
        epilog = textwrap.dedent('''Example:
        netcat.py -t 192.168.1.108 -p 5555 -l -c
        netcat.py -t 192.168.1.108 -p 5555 -l -c -u=mytest.txt
        netcat.py -t 192.168.1.108 -p 5555 -l -c -e=\"cat/etc/passwd\"
        echo 'ABC' | ./netcat.py -t 192.168.1.108 -p 135
        netcat.py -t 192.168.1.108 -p 5555 
       ''' )
    )
    # -c, -r, -u and -l applies only to listner, -t and -p define target listner
    parser.add_argument('-c', '--command', action = 'store_true', help = 'command shell') # -c sets up an interative shell
    parser.add_argument('-e', '--execute', help = 'execute specified command') # -e executes and specific command
    parser.add_argument('-l' '--listen', action = 'store_true', help = 'listen') # -l indicated that a listner should be set up
    parser.add_argument('-p', '--port', type = int, default = 5555, help = 'specified port') # -p specifies a port on which to communicate
    parser.add_argument('-t', '--target', default = 192.168.1.203, help = 'specified ip') # -t specifies target ip
    parser.add_argument('-u', '--upload', help = 'upload file') # -u specifies name of file to upload
    args = parser.parse_args()
    if args.listen:
        buffer = '' #if we are setting it as listner we invoke netcat object with empty string, otherwise we will send buffer content from stdin
    else:
        buffer = sys.stdin.read()
    nc = NetCat(args, buffer.encode())
    nc.run()
            