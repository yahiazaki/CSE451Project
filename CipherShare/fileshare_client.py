import base64
import json
import os
import random
import socket
import time

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from crypto_utils import derive_key_from_password, hash_password, verify_password, hash_file_bytes
from fileshare_peer import FileSharePeer


class FileShareClient:
    def __init__(self, host="localhost", port=1234):
        self.derived_key = None
        self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.peer_client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_address = (host, port)
        self.username = None
        self.session_key = None
        self.peer_server = None
        self.address = None
        self.port = None
        self.userFiles = {}
        self.active_session = {}

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
                parts = response.split(":")
                self.username = username
                self.derived_key = parts[2]  # get hashed password
                self.session_key = {
                    "username": username,
                    "key":  parts[1],
                    "expires_at": time.time() + 60,  # expires in 1 hour
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

    def check_and_renew_session(self):
        if not self.session_key:
            return False
        if time.time() <= self.session_key["expires_at"]:
            self.client_socket.sendall(b"SESSION_EXPIRED")
            response = self.client_socket.recv(1024).decode()
            self.session_key = {
                "username": self.username,
                "key": response,
                "expires_at": time.time() + 60,  # expires in 1 hour
            }
        return True

    def upload_file(self, filepath):
        try:
            if self.check_and_renew_session():
                # Extract the filename from the filepath
                filename = os.path.basename(filepath)
                print(f"Uploading {filename}...")

                # Send the command and filename together in one message, separated by a space
                message = f"UPLOAD {filename}"
                self.client_socket.send(message.encode())
                self.peer_server.shared_files[filename] = filepath
                return "SUCCESS"
            else:
                print("Session invalid")
                return "INVALID TOKEN"
        except Exception as e:
            print(f"Upload error: {e}")

    def download_file(self, filename, destination_path, aes_key):
        try:
            if not self.check_and_renew_session():
                print("Session invalid")
                return "INVALID TOKEN"

            self.peer_client_socket.sendall(f"DOWNLOAD {filename}".encode())
            if self.peer_client_socket.recv(1024) != b"OK":
                print(f"File {filename} does not exist on peer.")
                return "ERROR"

            iv = self.peer_client_socket.recv(16)
            print(f"Received key: {aes_key}")
            print(f"Received IV: {iv}")

            encrypted_data = bytearray()
            while True:
                chunk = self.peer_client_socket.recv(1024)
                if not chunk:
                    break
                encrypted_data.extend(chunk)

            # Split encrypted data and hash
            delimiter = b"HASH_START"
            if delimiter not in encrypted_data:
                print("Delimiter not found. Possibly corrupted transmission.")
                return "HASH ERROR"

            delim_index = encrypted_data.index(delimiter)
            file_bytes = encrypted_data[:delim_index]
            received_hash = encrypted_data[delim_index + len(delimiter):].decode()

            # Verify hash
            calculated_hash = hash_file_bytes(file_bytes)
            if calculated_hash != received_hash:
                print("Hash mismatch! File may be corrupted or tampered with.")
                return "HASH ERROR"

            # Now decrypt after verifying
            cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
            decryptor = cipher.decryptor()
            unpadder = padding.PKCS7(128).unpadder()
            decrypted_data = bytearray()

            for i in range(0, len(file_bytes), 1024):
                chunk = file_bytes[i:i + 1024]
                decrypted_chunk = decryptor.update(chunk)
                decrypted_data.extend(unpadder.update(decrypted_chunk))

            decrypted_data.extend(unpadder.update(decryptor.finalize()) + unpadder.finalize())

            with open(destination_path, 'wb') as file:
                file.write(decrypted_data)

            print(f"File {filename} downloaded and verified successfully.")
            return "SUCCESS"

        except Exception as e:
            print(f"Download error: {e}")
            return "ERROR"

    def search_files(self):
        try:
            self.peer_client_socket.send(b"SEARCH")
            file_list = self.peer_client_socket.recv(1024).decode()
            if file_list == "EMPTYLIST":
                return None
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

    def dh_key_exchange_client(self):

        self.peer_client_socket.sendall(b"KEYEXCHANGE")
        p = 13
        g = 2  # Generator (often 2 or 5)

        # Generate the peer's private key
        private_key = random.randint(1, p - 1)

        # Calculate the public key: A = g^a % p
        public_key = pow(g, private_key, p)

        self.peer_client_socket.send(f"{p},{g},{public_key}".encode())

        peer_response = self.peer_client_socket.recv(1024).decode()
        peer_public_key = int(peer_response)

        shared_key = pow(peer_public_key, private_key, p)

        aes_key = shared_key.to_bytes(16, byteorder='big')
        return aes_key
