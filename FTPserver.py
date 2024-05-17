import json
import os
from datetime import datetime
from pyftpdlib.authorizers import DummyAuthorizer
from pyftpdlib.handlers import FTPHandler
from pyftpdlib.servers import FTPServer
from pyftpdlib.filesystems import AbstractedFS
import logging

# Configure logging
logging.basicConfig(level=logging.DEBUG)

# Global variable to track incorrect login attempts
incorrect_login_count = 1

# Load or initialize credentials
credentials_file = 'credentials.json'

try:
    with open(credentials_file, 'r') as f:
        credentials = json.load(f)
except FileNotFoundError:
    credentials = {}

# Function to add a user
def add_user(username, password):
    credentials[username] = password
    with open(credentials_file, 'w') as f:
        json.dump(credentials, f)

# Example of adding a user
add_user('user1', 'pass1')
add_user('user2', 'pass2')

# Custom filesystem class to avoid invalid timestamps
class CustomFS(AbstractedFS):
    def format_mlsx(self, basedir, listing, perms, facts, ignore_err=True):
        formatted = []
        for entry in listing:
            if isinstance(entry, tuple) and len(entry) == 2:
                basename, st = entry
                try:
                    if not isinstance(st.st_mtime, (int, float)):
                        st.st_mtime = datetime.now().timestamp()
                    formatted.append(super().format_mlsx(basedir, [(basename, st)], perms, facts, ignore_err)[0])
                except OSError as e:
                    if ignore_err:
                        continue
                    raise
        return iter(formatted)

# Create a custom authorizer class to check credentials from the JSON file
class JSONAuthorizer(DummyAuthorizer):
    def validate_authentication(self, username, password, handler):
        logging.debug(f"Validating user: {username}")
        if username in credentials:
            logging.debug(f"Stored password: {credentials[username]}, Provided password: {password}")
            if credentials[username] == password:
                return True
        logging.debug("Authentication failed")
        return False

# Custom FTP handler to enforce authentication checks with retries and additional logging
class CustomFTPHandler(FTPHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.command_timestamps = {}

    def log_event(self, event_type, username=None, password=None, latency=None):
        ip = self.remote_ip
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        logging.info(f"{event_type} | IP: {ip} | Username: {username} | Password: {password} | Timestamp: {timestamp} | Latency: {latency}ms")

    def ftp_USER(self, username):
        self.command_timestamps['USER'] = datetime.now()
        logging.debug(f"Received USER command for username: {username}")
        super().ftp_USER(username)

    def ftp_PASS(self, password):
        global incorrect_login_count
        username = self.username
        self.log_event("Login Attempt", username, password)
        logging.debug(f"Authenticating user: {username}")
        if not self.authorizer.validate_authentication(username, password, self):
            incorrect_login_count += 1
            logging.debug(f"Failed login attempt {incorrect_login_count} for user: {username}")
            self.respond("530 Authentication failed.")
            logging.debug(f"Incorrect login count is now: {incorrect_login_count}")
            if incorrect_login_count >= 3:
                logging.debug(f"Disconnecting user {username} after {incorrect_login_count} failed attempts")
                self.respond("530 Too many failed login attempts. Disconnecting.")
                self.close_when_done()
                exit()
                return
        else:
            logging.debug("Authentication successful.")
            incorrect_login_count = 0  # Reset the counter on successful login
            self.authenticated = True
            self.username = username
            home_dir = self.authorizer.get_home_dir(username)
            if not isinstance(home_dir, str):
                home_dir = str(home_dir)
            if not os.path.exists(home_dir):
                os.makedirs(home_dir)
            self.fs = CustomFS(home_dir, self)
            self.respond("230 Login successful.")

            if 'USER' in self.command_timestamps:
                latency = (datetime.now() - self.command_timestamps['USER']).total_seconds() * 1000  # Latency in milliseconds
                self.log_event("Login Successful", username, password, latency)

    def handle_close(self):
        global incorrect_login_count
        if not self.authenticated:
            logging.debug(f"Closing connection. Current incorrect login count: {incorrect_login_count}")
        super().handle_close()

    def ftp_NOOP(self):
        if not self.username:
            self.log_event("Port Scan Detected")
            self.respond("530 Port scan detected. Disconnecting.")
            self.close_when_done()
        else:
            super().ftp_NOOP()

def main():
    authorizer = JSONAuthorizer()

    # Give full permissions to users in the credentials
    for username in credentials:
        home_dir = f'./ftp_home/{username}'
        if not os.path.exists(home_dir):
            os.makedirs(home_dir)
        authorizer.add_user(username, credentials[username], homedir=home_dir, perm='elradfmw')

    handler = CustomFTPHandler
    handler.authorizer = authorizer

    server = FTPServer(('0.0.0.0', 21), handler)
    server.serve_forever()

if __name__ == '__main__':
    main()
