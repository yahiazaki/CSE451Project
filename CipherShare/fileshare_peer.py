import json
import random
import socket
import threading
import os

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from crypto_utils import hash_file_bytes


class FileSharePeer:
    def __init__(self, sock):
        self.AES_key = None
        self.peer_socket = sock
        self.shared_files = {}
        self.local_files = {}
        self.file_broadcast_port = 60001  # same as client
        threading.Thread(target=self.listen_for_file_broadcasts, daemon=True).start()
        threading.Thread(target=self.start_peer).start()

    def start_peer(self):
        self.peer_socket.listen(5)
        print(f"Peer listening....")

        while True:
            client_socket, client_address = self.peer_socket.accept()
            client_thread = threading.Thread(target=self.handle_client_connection, args=(client_socket, client_address))
            client_thread.start()

    def listen_for_file_broadcasts(self):
        udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        udp_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        udp_socket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        udp_socket.bind(('', self.file_broadcast_port))
        print(f"[UDP File Listener] Listening on port {self.file_broadcast_port} for file announcements...")

        while True:
            try:
                data, addr = udp_socket.recvfrom(4096)
                file_info = json.loads(data.decode())
                if file_info.get("type") == "UPLOAD":
                    filename = file_info["filename"]
                    uploader = file_info["username"]
                    self.shared_files[filename] = {
                        "uploader": uploader,
                        "address": file_info["address"],
                        "port": file_info["port"]
                    }
                    print(f"[UDP File Received] {filename} shared by {uploader}")
            except Exception as e:
                print(f"[UDP File Listener] Error: {e}")

    def handle_client_connection(self, client_socket, client_address):
        print(f"Accepted connection from {client_address}")
        try:
            while True:
                msg = client_socket.recv(1024).decode().split()
                command = msg[0]
                print(f"Received command: {command}")

                if command == "DOWNLOAD":
                    filename = msg[1]
                    print(f"Received filename for download: {filename}")
                    self.download_file(client_socket, filename, self.AES_key)
                elif command == "SEARCH":
                    self.search_files(client_socket)
                elif command == "LIST_FILES":
                    if not self.shared_files:
                        client_socket.send(b'{}')  # Send empty JSON dict
                    else:
                        # Send only filename and uploader
                        filtered = {
                            fname: info["uploader"]
                            for fname, info in self.shared_files.items() if info["uploader"] != msg[1]
                        }
                        client_socket.send(json.dumps(filtered).encode())

                elif command == "KEYEXCHANGE":
                    self.AES_key = self.dh_key_exchange_peer(client_socket)
                    print(f"Received AES key for file transfer: {self.AES_key}")
                elif command == "QUIT":
                    break
                else:
                    print(f"Unknown command: {command}")

        except Exception as e:
            print(f"Error handling client {client_address}: {e}")
        finally:
            print(f"Closing connection with {client_address}")
            client_socket.close()

    def download_file(self, client_socket, filename, aes_key):
        print(f"Attempting to download file: {filename}")

        saved_path = self.local_files.get(filename)
        if saved_path is None:
            print(f"File {filename} not found in shared files.")
            client_socket.send(b'ERROR')
            return

        client_socket.send(b'OK')
        iv = os.urandom(16)
        print(f"Generated IV: {iv}")
        client_socket.send(iv)

        cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        padder = padding.PKCS7(128).padder()
        encrypted_data = bytearray()

        try:
            with open(saved_path, 'rb') as file:
                while chunk := file.read(1024):
                    padded = padder.update(chunk)
                    encrypted_chunk = encryptor.update(padded)
                    encrypted_data.extend(encrypted_chunk)

            final_block = padder.finalize()
            final_encrypted = encryptor.update(final_block) + encryptor.finalize()
            encrypted_data.extend(final_encrypted)

            # Compute hash BEFORE sending the file
            file_hash = hash_file_bytes(encrypted_data)
            print(f"Encrypted file hash (SHA-256): {file_hash}")

            # Send encrypted file
            client_socket.sendall(encrypted_data)

            # Delimiter before sending hash
            client_socket.sendall(b"HASH_START" + file_hash.encode())

            client_socket.shutdown(socket.SHUT_WR)
            print(f"File {filename} sent successfully.")
        except Exception as e:
            print(f"Error sending file {filename}: {e}")
            client_socket.send(b'ERROR')

    def search_files(self, client_socket):
        file_list = '\n'.join(self.local_files.keys())
        if file_list == "":
            client_socket.send(b'EMPTYLIST')
        else:
            client_socket.send(file_list.encode())

    def dh_key_exchange_peer(self, client_socket):
        client_data = client_socket.recv(1024).decode()
        p, g, client_public_key = map(int, client_data.split(','))

        # Generate the client's private key
        private_key = random.randint(1, p - 1)

        # Calculate the client's public key: B = g^b % p
        public_key = pow(g, private_key, p)

        client_socket.send(str(public_key).encode())

        shared_key = pow(client_public_key, private_key, p)

        aes_key = shared_key.to_bytes(16, byteorder='big')

        return aes_key