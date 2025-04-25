import tkinter as tk
from tkinter import filedialog, simpledialog, messagebox

import Login_client
from fileshare_client import FileShareClient
import os


class home_GUI:
    def __init__(self, client):
        self.files_top = None
        self.available_peers = None
        self.peer_frame = None
        self.root_main = None
        self.client = client
        self.home_gui()

    def handle_upload(self):
        session = self.client.check_and_renew_session()
        if session:
            filepath = filedialog.askopenfilename(title="Select File to Upload")
            print(filepath)
            if filepath:
                result = self.client.upload_file(filepath)
                if result == "SUCCESS":
                    messagebox.showinfo("Upload", f"File '{os.path.basename(filepath)}' uploaded successfully!")
                else:
                    messagebox.showerror("Upload", "File upload failed.")
        else:
            messagebox.showinfo("Session Expired", "Your session has expired. Please log in again.")
            self.root_main.destroy()
            Login_client.login_gui()

    def handle_download(self):
        filename = simpledialog.askstring("Download", "Enter filename to download:")
        if filename:
            save_path = filedialog.asksaveasfilename(title="Save As", initialfile=filename)
            if save_path:
                result = self.client.download_file(filename, save_path)
                if result == "SUCCESS":
                    messagebox.showinfo("Download", f"File '{filename}' downloaded successfully!")
                else:
                    messagebox.showerror("Download", f"Failed to download file '{filename}'.")

    def handle_list_files(self):
        files = self.client.get_available_files()
        session = self.client.check_and_renew_session()
        if session:
            if not files:
                messagebox.showinfo("Files", "No files available.")
            else:
                top = tk.Toplevel()
                top.title("Available Files")
                top.geometry("300x400")

                for file_name, username in files.items():
                    file_btn = tk.Button(top, text=f"{file_name} from {username}")
                    file_btn.pack(pady=5)
        else:
            messagebox.showinfo("Session Expired", "Your session has expired. Please log in again.")
            self.root_main.destroy()
            Login_client.login_gui()

    def handle_connect_peer(self, peer_address):

        try:
            session = self.client.check_and_renew_session()
            if session:
                if self.client.connect_to_peer(peer_address['address'], peer_address['port']):
                    messagebox.showinfo("Connect", f"Connected to peer successfully!")
                    self.root_main.destroy()
                    self.peer_control_window()
                else:
                    messagebox.showerror("Connect", "Failed to connect to peer.")
            else:
                messagebox.showinfo("Session Expired", "Your session has expired. Please log in again.")
                self.available_peers.destroy()
                self.root_main.destroy()
                Login_client.login_gui()
        except Exception as e:
            messagebox.showerror("Connect", f"Failed to connect to peer: {e}")

    def list_available_peers(self):
        session = self.client.check_and_renew_session()
        if session:
            peers = self.client.get_user_addresses()
            if not peers:
                messagebox.showinfo("Peers", "No peers available.")
            else:
                self.available_peers = tk.Toplevel()
                self.available_peers.title("Available Peers")
                self.available_peers.geometry("300x400")
                tk.Label(self.available_peers, text="Click a peer to connect:", font=("Arial", 12)).pack(pady=10)

                for peer_name, peer_address in peers.items():
                    peer_btn = tk.Button(self.available_peers, text=peer_name, command=lambda pa=peer_address: self.handle_connect_peer(pa))
                    peer_btn.pack(pady=5)
        else:
            messagebox.showinfo("Session Expired", "Your session has expired. Please log in again.")
            self.root_main.destroy()
            Login_client.login_gui()

    def peer_control_window(self):
        self.peer_frame = tk.Tk()
        self.peer_frame.title(f"Peer Window")
        self.peer_frame.geometry("300x200")

        disconnect_btn = tk.Button(self.peer_frame, text="Disconnect", width=20, command=self.disconnect)
        disconnect_btn.pack(pady=10)

        list_files_btn = tk.Button(self.peer_frame, text="List Peer Files", width=20, command=self.list_peer_files)
        list_files_btn.pack(pady=10)

    def disconnect(self):
        try:
            session = self.client.check_and_renew_session()
            if session:
                self.client.close_peer_connection()
                messagebox.showinfo("Disconnect", "Disconnected from peer successfully.")
                self.peer_frame.destroy()
                self.home_gui()
            else:
                messagebox.showinfo("Session Expired", "Your session has expired. Please log in again.")
                self.peer_frame.destroy()
                Login_client.login_gui()
        except Exception as e:
            messagebox.showerror("Disconnect", f"Failed to disconnect: {e}")

    def list_peer_files(self):

        session = self.client.check_and_renew_session()

        if session:
            files = self.client.search_files()
            if not files:
                messagebox.showinfo("Files", "No files available from this peer.")
            else:
                self. files_top = tk.Toplevel()
                self.files_top.title("Files from Peer")
                self.files_top.geometry("300x400")
                tk.Label(self.files_top, text="Click a file to download:", font=("Arial", 12)).pack(pady=10)

                def download_selected_file(file_name_one):
                    download_session = self.client.check_and_renew_session()
                    if download_session:
                        save_path = filedialog.asksaveasfilename(title="Save As", initialfile=file_name_one)
                        if save_path:
                            key = self.client.dh_key_exchange_client()
                            result = self.client.download_file(file_name_one, save_path,key)
                            if result == "SUCCESS":
                                messagebox.showinfo("Download", f"File '{file_name_one}' downloaded successfully!")
                            else:
                                messagebox.showerror("Download", f"Failed to download '{file_name_one}'.")
                    else:
                        messagebox.showinfo("Session Expired", "Your session has expired. Please log in again.")
                        self.files_top.destroy()
                        self.peer_frame.destroy()
                        Login_client.login_gui()

                for file_name in files:
                    file_btn = tk.Button(self.files_top, text=file_name,
                                         command=lambda fn=file_name: download_selected_file(fn))
                    file_btn.pack(pady=5)
        else:
            messagebox.showinfo("Session Expired", "Your session has expired. Please log in again.")
            self.peer_frame.destroy()
            Login_client.login_gui()

    def home_gui(self):
        self.root_main = tk.Tk()
        self.root_main.title("File Sharing System")
        self.root_main.geometry("400x250")

        tk.Label(self.root_main, text="Welcome to CypherShare", font=("Helvetica", 14)).pack(pady=20)

        upload_btn = tk.Button(self.root_main, text="Upload File", width=20, command=self.handle_upload)
        upload_btn.pack(pady=10)

        list_btn = tk.Button(self.root_main, text="List Available Files", width=20, command=self.handle_list_files)
        list_btn.pack(pady=10)

        list_btn = tk.Button(self.root_main, text="Connect to a peer", width=20, command=self.list_available_peers)
        list_btn.pack(pady=10)

        self.root_main.mainloop()
