import socket
import threading
from datetime import datetime
import json

# Function to load credentials from a configuration file
def load_credentials(filename):
    with open(filename, 'r') as file:
        return json.load(file)

# Load credentials at startup
stored_credentials = load_credentials('credentials.json')

# Function to handle client connections
def handle_client(conn, address, ttl):
    try:
        login_attempts = 0
        while login_attempts < 3:
            conn.sendall(b'220 Welcome to Mock FTP Server\r\n')
            user_command = conn.recv(1024).decode('utf-8').strip()
            if user_command.startswith('USER'):
                username = user_command.split(' ')[1]
                conn.sendall(b'331 Please specify the password.\r\n')
            else:
                conn.sendall(b'500 Syntax error, command unrecognized.\r\n')
                continue

            pass_command = conn.recv(1024).decode('utf-8').strip()
            if pass_command.startswith('PASS'):
                password = pass_command.split(' ')[1]
            else:
                conn.sendall(b'500 Syntax error, command unrecognized.\r\n')
                continue

            # Check credentials
            if stored_credentials.get(username) == password:
                log_login_attempt(username, password, address, ttl, success=True)
                conn.sendall(b'230 Login successful.\r\n')
                break
            else:
                log_login_attempt(username, password, address, ttl, success=False)
                conn.sendall(b'530 Login incorrect.\r\n')
                login_attempts += 1

        if login_attempts >= 3:
            conn.sendall(b'421 Too many login attempts. Connection closed.\r\n')
    except Exception as e:
        print(f"Exception in handle_client: {e}")
    finally:
        try:
            if conn:
                conn.shutdown(socket.SHUT_RDWR)  # Properly shutdown the socket before closing
                conn.close()
        except Exception as e:
            print(f"Exception while closing the connection: {e}")

# Function to log login attempts
def log_login_attempt(username, password, address, ttl, success):
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    source_ip = address[0]
    status = 'SUCCESS' if success else 'FAILURE'
    log_line = f'{timestamp}, {source_ip}, {username}, {password}, {status}, TTL: {ttl}\n'
    with open('ftp_logs.txt', 'a') as log_file:
        log_file.write(log_line)

# Function to log port scan attempts
def log_port_scan(address, ttl):
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    source_ip = address[0]
    log_line = f'{timestamp}, {source_ip}, Port Scan Attempt, TTL: {ttl}\n'
    with open('ftp_logs.txt', 'a') as log_file:
        log_file.write(log_line)

# Function to get TTL from socket (this is platform dependent and may require raw sockets)
def get_ttl(sock):
    try:
        return sock.getsockopt(socket.IPPROTO_IP, socket.IP_TTL)
    except:
        return "Unknown"

# Function to start the server
def start_server():
    host = "0.0.0.0"  # Listen on all interfaces
    port = 21
    totalClients = int(input('Enter number of clients: '))
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind((host, port))
    sock.listen(totalClients)
    connections = []
    print("Initiating clients")

    # Accept connections
    for i in range(totalClients):
        try:
            sock.settimeout(60)  # Set a timeout of 60 seconds
            conn, address = sock.accept()
            ttl = get_ttl(sock)
            connections.append((conn, address, ttl))
            print("Connected with client", i + 1)
        except socket.timeout:
            print("Timeout: No more clients are connecting.")
            break

    # Handle connections
    for conn, address, ttl in connections:
        try:
            initial_data = conn.recv(1024).decode('utf-8').strip()
            
            if initial_data == '':
                log_port_scan(address, ttl)
                conn.close()
                continue
            
            client_handler = threading.Thread(target=handle_client, args=(conn, address, ttl))
            client_handler.start()
        except Exception as e:
            print(f"Exception while handling connection: {e}")
            try:
                if conn:
                    conn.shutdown(socket.SHUT_RDWR)  # Properly shutdown the socket before closing
                    conn.close()
            except Exception as e:
                print(f"Exception while closing the connection: {e}")

    # Closing connections
    for conn, address, ttl in connections:
        try:
            if conn:
                conn.shutdown(socket.SHUT_RDWR)  # Properly shutdown the socket before closing
                conn.close()
        except Exception as e:
            print(f"Exception while closing the connection: {e}")

if __name__ == "__main__":
    start_server()
