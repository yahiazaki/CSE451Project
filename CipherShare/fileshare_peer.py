import socket
import threading
import os


class FileSharePeer:
    def __init__(self, sock):
        self.peer_socket = sock
        self.shared_files = {}
        threading.Thread(target=self.start_peer).start()

    def start_peer(self):
        self.peer_socket.listen(5)
        print(f"Peer listening....")

        while True:
            client_socket, client_address = self.peer_socket.accept()
            client_thread = threading.Thread(target=self.handle_client_connection, args=(client_socket, client_address))
            client_thread.start()

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
                    self.download_file(client_socket, filename)
                elif command == "SEARCH":
                    self.search_files(client_socket)
                elif command == "QUIT":
                    break
                else:
                    print(f"Unknown command: {command}")

        except Exception as e:
            print(f"Error handling client {client_address}: {e}")
        finally:
            print(f"Closing connection with {client_address}")
            client_socket.close()

    def download_file(self, client_socket, filename):
        print(f"Attempting to download file: {filename}")

        saved_path = self.shared_files[filename] if filename in self.shared_files else None
        if saved_path is None:
            print(f"File {filename} not found in shared files.")
            client_socket.send(b'ERROR')
        else:
            client_socket.send(b'OK')
            try:
                with open(saved_path, 'rb') as file:
                    while chunk := file.read(1024):
                        client_socket.send(chunk)
                client_socket.shutdown(socket.SHUT_WR)
                print(f"File {filename} sent successfully.")
            except Exception as e:
                print(f"Error sending file {filename}: {e}")
                client_socket.send(b'ERROR')

    def search_files(self, client_socket):
        file_list = '\n'.join(self.shared_files.keys())
        client_socket.send(file_list.encode())
