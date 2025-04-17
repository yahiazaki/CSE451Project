import tkinter as tk
from tkinter import filedialog, simpledialog, messagebox
from fileshare_client import FileShareClient
import os


class home_GUI:
    def __init__(self, client):
        self.peer_frame = None
        self.root_main = None
        self.client = client
        self.home_gui()

    def handle_upload(self):
        filepath = filedialog.askopenfilename(title="Select File to Upload")
        print(filepath)
        if filepath:
            result = self.client.upload_file(filepath)
            if result == "SUCCESS":
                messagebox.showinfo("Upload", f"File '{os.path.basename(filepath)}' uploaded successfully!")
            else:
                messagebox.showerror("Upload", "File upload failed.")

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
        if not files:
            messagebox.showinfo("Files", "No files available.")
        else:
            top = tk.Toplevel()
            top.title("Available Files")
            top.geometry("300x400")

            for file_name, username in files.items():
                file_btn = tk.Button(top, text=f"{file_name} from {username}")
                file_btn.pack(pady=5)

    def handle_connect_peer(self, peer_address):

        try:
            if self.client.connect_to_peer(peer_address['address'], peer_address['port']):
                messagebox.showinfo("Connect", f"Connected to peer successfully!")
                self.root_main.destroy()
                self.peer_control_window()
            else:
                messagebox.showerror("Connect", "Failed to connect to peer.")
        except Exception as e:
            messagebox.showerror("Connect", f"Failed to connect to peer: {e}")

    def list_available_peers(self):
        peers = self.client.get_user_addresses()
        if not peers:
            messagebox.showinfo("Peers", "No peers available.")
        else:
            top = tk.Toplevel()
            top.title("Available Peers")
            top.geometry("300x400")
            tk.Label(top, text="Click a peer to connect:", font=("Arial", 12)).pack(pady=10)

            for peer_name, peer_address in peers.items():
                peer_btn = tk.Button(top, text=peer_name, command=lambda pa=peer_address: self.handle_connect_peer(pa))
                peer_btn.pack(pady=5)

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
            self.client.close_peer_connection()
            messagebox.showinfo("Disconnect", "Disconnected from peer successfully.")
            self.peer_frame.destroy()
            self.home_gui()
        except Exception as e:
            messagebox.showerror("Disconnect", f"Failed to disconnect: {e}")

    def list_peer_files(self):
        files = self.client.search_files()
        if not files:
            messagebox.showinfo("Files", "No files available from this peer.")
        else:
            files_top = tk.Toplevel()
            files_top.title("Files from Peer")
            files_top.geometry("300x400")
            tk.Label(files_top, text="Click a file to download:", font=("Arial", 12)).pack(pady=10)

            def download_selected_file(file_name_one):
                save_path = filedialog.asksaveasfilename(title="Save As", initialfile=file_name_one)
                if save_path:
                    result = self.client.download_file(file_name_one, save_path)
                    if result == "SUCCESS":
                        messagebox.showinfo("Download", f"File '{file_name_one}' downloaded successfully!")
                    else:
                        messagebox.showerror("Download", f"Failed to download '{file_name_one}'.")

            for file_name in files:
                file_btn = tk.Button(files_top, text=file_name,
                                     command=lambda fn=file_name: download_selected_file(fn))
                file_btn.pack(pady=5)

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
