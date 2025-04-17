import base64
import json
import os
import socket
import time

from crypto_utils import derive_key_from_password, hash_password, verify_password
from fileshare_peer import FileSharePeer


class FileShareClient:
    def __init__(self, host="localhost", port=1234):
        self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.peer_client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_address = (host, port)
        self.username = None
        self.session_key = None
        self.peer_server = None
        self.address = None
        self.port = None
        self.userFiles = {}

    def connect_to_authentication(self):
        try:
            self.client_socket.connect(self.server_address)
            print(f"Connected to server at {self.server_address}")
            return True
        except Exception as e:
            print(f"Error connecting to server {self.server_address}: {e}")
            return False

    def connect_to_peer(self, host, port):
        try:
            self.peer_client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            port = int(port)
            self.peer_client_socket.connect((host, port))
            print(f"Connected to peer at {host}:{port}")
            return True
        except Exception as e:
            print(f"Error connecting to peer {host}:{port} {e}")
            return False

    def register_user(self, username, password):
        try:
            salt = os.urandom(16)
            derived_key = derive_key_from_password(password, salt)
            hashed_password = hash_password(password)
            self.client_socket.sendall(
                f"REGISTER {username} {hashed_password} {derived_key}".encode()
            )
            response = self.client_socket.recv(1024).decode()
            return response
        except Exception as e:
            print(f"Registration error: {e}")
            return "ERROR"

    def login_user(self, username, password):
        try:
            self.client_socket.sendall(f"LOGIN {username} {password}".encode())
            response = self.client_socket.recv(1024).decode()
            print(response)
            if response.startswith("SESSION:"):
                self.username = username
                self.session_key = {
                    "key": response.split(":")[1],
                    "expires_at": time.time() + 3600,  # expires in 1 hour
                }
                peer_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                peer_socket.bind(("0.0.0.0", 0))
                address, port = peer_socket.getsockname()
                self.peer_server = FileSharePeer(peer_socket)
                self.client_socket.sendall(f"{address} {port}".encode())
                return "SUCCESS"
            else:
                print("Login failed:", response)
                self.client_socket.close()
                self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self.connect_to_authentication()
                return response
        except Exception as e:
            print(f"Login error: {e}")
            return "ERROR"

    def is_session_valid(self):
        if not self.session_key:
            return False
        return time.time() < self.session_key["expires_at"]

    def upload_file(self, filepath):
        try:
            # Extract the filename from the filepath
            filename = os.path.basename(filepath)
            print(f"Uploading {filename}...")

            # Send the command and filename together in one message, separated by a space
            message = f"UPLOAD {filename}"
            self.client_socket.send(message.encode())
            self.peer_server.shared_files[filename] = filepath
            return "SUCCESS"
        except Exception as e:
            print(f"Upload error: {e}")

    def download_file(self, filename, destination_path):
        try:
            self.peer_client_socket.sendall(
                f"DOWNLOAD {filename}".encode()
            )  # Send download command
            if self.peer_client_socket.recv(1024) == b"OK":  # Confirm file exists
                with open(destination_path, "wb") as file:
                    while chunk := self.peer_client_socket.recv(1024):
                        file.write(chunk)

                print(f"File {filename} downloaded successfully.")
                return "SUCCESS"
            else:
                print(f"File {filename} does not exist on peer.")
                return "ERROR"
        except Exception as e:
            print(f"Download error: {e}")
            return "ERROR"

    def search_files(self):
        try:
            self.peer_client_socket.send(b"SEARCH")
            file_list = self.peer_client_socket.recv(1024).decode()
            return file_list.split()
        except Exception as e:
            print(f"Error searching files: {e}")
            return []

    def get_available_files(self):
        try:
            self.client_socket.sendall(b"AVAILABLE_FILES")
            self.userFiles = json.loads(self.client_socket.recv(2048).decode())
            self.userFiles = {
                k: v for k, v in self.userFiles.items() if v != self.username
            }
            return self.userFiles
        except Exception as e:
            print(f"Error in file sending {e}")

    def get_user_addresses(self):
        try:
            self.client_socket.sendall(f"USER_ADDRESSES".encode())
            active_users = json.loads(self.client_socket.recv(2048).decode())
            if self.username in active_users:
                del active_users[self.username]
            return active_users
        except Exception as e:
            print(f"Error in retrieving user {e}")

    def close_peer_connection(self):
        if self.peer_client_socket:
            try:
                self.peer_client_socket.close()
                return True
            except Exception as e:
                print("Error closing socket: ", e)
                return False
        return False
