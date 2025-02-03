import paramiko

def ssh_command(ip, port, user, passwd, cmd):
    """
    Connects to an SSH server and executes a single command.
    
    Args:
        ip (str): Target server IP address.
        port (int): SSH port number.
        user (str): SSH username.
        passwd (str): SSH password.
        cmd (str): The command to execute.

    Returns:
        None
    """
    # Create an SSH client instance
    client = paramiko.SSHClient()
    
    # Automatically accept unknown SSH keys (not recommended for production)
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    # Connect to the SSH server
    client.connect(ip, port=port, username=user, password=passwd)

    # Execute the command on the remote server
    _, stdout, stderr = client.exec_command(cmd)

    # Retrieve command output and error messages
    output = stdout.readlines() + stderr.readlines()
    
    # Print the command output
    if output:
        print('--- Output ---')
        for line in output:
            print(line.strip())  # Print each line without extra spaces

if __name__ == '__main__':
    import getpass  # Securely prompt for password input

    # Ask the user for SSH login credentials
    user = input('Username: ')
    password = getpass.getpass()

    # Ask for the server IP, defaulting to 192.168.1.203 if not provided
    ip = input('Enter server IP: ') or '192.168.1.203'

    # Ask for the SSH port, defaulting to 2222 if not provided
    port = input('Enter port or <CR>: ') or 2222

    # Ask for a command to execute, defaulting to 'id' if not provided
    cmd = input('Enter command or <CR>: ') or 'id'

    # Execute the command on the remote server
    ssh_command(ip, port, user, password, cmd)
