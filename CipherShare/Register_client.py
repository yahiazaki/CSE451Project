import tkinter as tk
from tkinter import messagebox
from fileshare_client import FileShareClient
import Login_client
import re

client = FileShareClient()
client.connect_to_authentication()


def register_gui():
    root = tk.Tk()
    root.title("Register")
    root.geometry("400x300")

    tk.Label(root, text="Username:").pack()
    username_entry = tk.Entry(root)
    username_entry.pack()

    tk.Label(root, text="Password:").pack()
    password_entry = tk.Entry(root, show="*")
    password_entry.pack()

    def validate_password(password):
        if len(password) < 8 or not re.search(r'[A-Z]', password) or not re.search(r'[a-z]', password) or not re.search(
                r'[$&@_]', password):
            messagebox.showerror("Error",
                                 "Password must be at least 8 characters long, contain upper and lower case letters, and include at least one special character ($, &, _, @).")
            return False  # Return False to indicate invalid password
        return True  # Return True if the password is valid

    def handle_register():
        username = username_entry.get()
        password = password_entry.get()

        if validate_password(password):
            response = client.register_user(username, password)
            if response == "SUCCESS":
                messagebox.showinfo("Success", "Registration Successful")
            else:
                messagebox.showerror("Error", response)
        else:
            return

    def go_to_login():
        root.destroy()
        Login_client.login_gui()

    tk.Button(root, text="Register", command=handle_register).pack(pady=10)
    tk.Button(root, text="Go to Login", command=go_to_login).pack()

    root.mainloop()


if __name__ == "__main__":
    register_gui()
