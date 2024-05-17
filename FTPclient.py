import socket

def send_ftp_commands(sock):
    try:
        # Prompt for username
        username = input("Enter username: ")
        sock.sendall(f'USER {username}\r\n'.encode())
        response = sock.recv(1024)
        print('Received:', response.decode('utf-8').strip())

        # Prompt for password
        password = input("Enter password: ")
        sock.sendall(f'PASS {password}\r\n'.encode())
        response = sock.recv(1024)
        print('Received:', response.decode('utf-8').strip())
    except Exception as e:
        print(f"Exception in send_ftp_commands: {e}")

if __name__ == "__main__":
    host = input("Enter server IP address: ")  # Allows entering the external host IP
    port = int(input("Enter server port: "))
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((host, port))
    
    while True:
        send_ftp_commands(sock)
        another = input("Do you want to attempt another login? (yes/no): ")
        if another.lower() != 'yes':
            break
    
    sock.close()
    print('Connection closed.')
