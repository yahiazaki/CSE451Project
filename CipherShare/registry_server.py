import os
import socket
import threading
import json
import base64
import uuid

from cryptography.hazmat.primitives import serialization

from crypto_utils import verify_password


class AuthenticationServer:
    def __init__(self, port):
        self.peer_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.port = port
        self.host = '0.0.0.0'
        self.users = {}
        self.fileInfo = {}
        self.activeUsers = {}

    def start_peer(self):
        self.peer_socket.bind((self.host, self.port))
        self.peer_socket.listen(5)
        print(f"Peer listening on port {self.port}")

        while True:
            client_socket, client_address = self.peer_socket.accept()
            threading.Thread(target=self.handle_client_connection, args=(client_socket, client_address)).start()

    def handle_client_connection(self, client_socket, client_address, file_name="hashed_password.json"):
        activeUsername = None

        def load_users():
            if os.path.exists(file_name):
                with open(file_name, "r") as f:
                    return json.load(f)
            return {}

        def save_users(users):
            with open(file_name, "w") as f:
                json.dump(users, f, indent=4)

        while True:
            try:
                response = client_socket.recv(1024).decode().split()
                command = response[0]

                if command == "REGISTER":
                    username = response[1]
                    hashed_password = response[2]
                    derived_key = response[3]

                    users = load_users()

                    if username in users:
                        client_socket.sendall(b"ERROR: Username already exists")
                    else:
                        users[username] = {
                            "hashed_password": hashed_password,
                            "derived_key": derived_key,
                        }
                        save_users(users)
                        print("Updated users:", users)
                        client_socket.sendall(b"SUCCESS")

                elif command == "LOGIN":
                    username = response[1]
                    password = response[2]

                    users = load_users()

                    if username in users:
                        if username in self.activeUsers:
                            client_socket.sendall(b"ERROR: User already logged in")
                            continue
                        hashed = users[username]['hashed_password']
                        if verify_password(password, hashed):
                            session_id = str(uuid.uuid4())
                            client_socket.sendall(f"SESSION:{session_id}:{hashed}".encode())
                            address, port = client_socket.recv(1024).decode().split()
                            self.activeUsers[username] = {
                                "address": client_address[0],
                                "port": port
                            }
                            activeUsername = username
                        else:
                            client_socket.sendall(b"ERROR: Invalid credentials")
                    else:
                        client_socket.sendall(b"ERROR: Invalid credentials")

                elif command == "UPLOAD":
                    file_name = response[1]
                    self.fileInfo[file_name] = activeUsername

                elif command == "AVAILABLE_FILES":
                    client_socket.sendall(json.dumps(self.fileInfo).encode())

                elif command == "USER_ADDRESSES":
                    client_socket.sendall(json.dumps(self.activeUsers).encode())
                elif command == "QUIT":
                    break
                elif command == "SESSION_EXPIRED":
                    session_id = str(uuid.uuid4())
                    client_socket.sendall(session_id.encode())

            except Exception as e:
                print(f"Error handling client {client_address}: {e}")
                break

        client_socket.close()
        if activeUsername in self.activeUsers:
            del self.activeUsers[activeUsername]


if __name__ == '__main__':
    peer = AuthenticationServer(port=1234)
    peer.start_peer()
