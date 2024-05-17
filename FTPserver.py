import json
from datetime import datetime
from pyftpdlib.authorizers import DummyAuthorizer
from pyftpdlib.handlers import FTPHandler
from pyftpdlib.servers import FTPServer
from pyftpdlib.filesystems import AbstractedFS
import logging

# Configure logging
logging.basicConfig(level=logging.DEBUG)

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

# Custom filesystem class to handle invalid timestamps
class CustomFS(AbstractedFS):
    def format_mlsx(self, basedir, listing, perms, facts, ignore_err=True):
        formatted = []
        for entry in listing:
            if isinstance(entry, tuple) and len(entry) == 2:
                basename, st = entry
                try:
                    mtime = datetime.fromtimestamp(st.st_mtime)
                    if mtime.year < 1970 or mtime.year > 2038:  # Handle invalid timestamps
                        st.st_mtime = datetime.now().timestamp()
                    formatted.append(super().format_mlsx(basedir, [(basename, st)], perms, facts, ignore_err)[0])
                except OSError as e:
                    if ignore_err:
                        continue
                    raise
        return iter(formatted)  # Ensure the result is an iterator

# Create a custom authorizer class to check credentials from the JSON file
class JSONAuthorizer(DummyAuthorizer):
    def validate_authentication(self, username, password, handler):
        # Log for debugging purposes
        logging.debug(f"Validating user: {username}")
        if username in credentials:
            logging.debug(f"Stored password: {credentials[username]}, Provided password: {password}")
            if credentials[username] == password:
                return True
        logging.debug("Authentication failed")
        return False

# Custom FTP handler to enforce authentication checks with retries
class CustomFTPHandler(FTPHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.failed_login_attempts = 0

    def ftp_PASS(self, password):
        username = self.username
        logging.debug(f"Authenticating user: {username}")
        if not self.authorizer.validate_authentication(username, password, self):
            self.failed_login_attempts += 1
            logging.debug(f"Failed login attempt {self.failed_login_attempts} for user: {username}")
            self.respond("530 Authentication failed.")
            if self.failed_login_attempts >= 3:
                self.respond("530 Too many failed login attempts. Disconnecting.")
                self.close_when_done()
            return
        logging.debug("Authentication successful.")
        self.failed_login_attempts = 0
        self.username = username
        self._login_user(username)
        self.respond("230 Login successful.")

def main():
    authorizer = JSONAuthorizer()

    # Give full permissions to users in the credentials
    for username in credentials:
        authorizer.add_user(username, credentials[username], homedir='/', perm='elradfmw')

    handler = CustomFTPHandler
    handler.authorizer = authorizer
    handler.abstracted_fs = CustomFS

    server = FTPServer(('0.0.0.0', 21), handler)
    server.serve_forever()

if __name__ == '__main__':
    main()
