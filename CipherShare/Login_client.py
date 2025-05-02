import tkinter as tk
from tkinter import messagebox
import time
import socket
import base64
import hashlib
from cryptography.fernet import Fernet

import Home_client
from crypto_utils import key_from_hash, save_credentials
from fileshare_client import FileShareClient

# Create client and connect
client = FileShareClient()
client.connect_to_authentication()


# Auto-login if credentials exist and are correct
def auto_login_if_possible():
    try:
        with open("credentials.enc", "rb") as f:
            encrypted_credentials = f.read()

        with open("user_hashed_password.txt", "r") as f:
            derived_key = f.read()

        fernet_key = key_from_hash(derived_key)
        fernet = Fernet(fernet_key)

        decrypted = fernet.decrypt(encrypted_credentials).decode()
        username, password = decrypted.split(":")

        response = client.login_user(username, password)
        if response == "SUCCESS":
            print("Auto-login successful.")
            Home_client.home_GUI(client)
            return True  # Auto-login succeeded

    except Exception as e:
        print(f"Auto-login failed: {e}")

    return False  # Auto-login failed


# GUI for login window
def login_gui():
    global root
    root = tk.Tk()
    root.title("Login")
    root.geometry("400x300")

    tk.Label(root, text="Username:").pack()
    username_entry = tk.Entry(root)
    username_entry.pack()

    tk.Label(root, text="Password:").pack()
    password_entry = tk.Entry(root, show="*")
    password_entry.pack()

    # Remember Me checkbox
    remember_var = tk.IntVar()
    tk.Checkbutton(root, text="Remember Me", variable=remember_var).pack(pady=5)

    # Handle login button press
    def handle_login():
        username = username_entry.get()
        password = password_entry.get()

        response = client.login_user(username, password)
        if response == "SUCCESS":
            messagebox.showinfo("Success", "Login Successful")

            if remember_var.get() == 1:
                try:
                    save_credentials(username, password, client.derived_key)
                    with open("user_hashed_password.txt", "w") as f:
                        f.write(client.derived_key)
                except Exception as e:
                    print(f"Error saving credentials: {e}")
                    messagebox.showerror("Error", "Failed to save login information.")

            root.destroy()
            Home_client.home_GUI(client)

        else:
            messagebox.showerror("Error", response)

    # Login button
    tk.Button(root, text="Login", command=handle_login).pack(pady=10)

    root.mainloop()


# Main entry point
if __name__ == "__main__":
    if not auto_login_if_possible():
        login_gui()
