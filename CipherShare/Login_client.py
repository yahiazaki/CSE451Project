import tkinter as tk
from tkinter import messagebox

import Home_client
from fileshare_client import FileShareClient

client = FileShareClient()
client.connect_to_authentication()


def login_gui():
    root = tk.Tk()
    root.title("Login")
    root.geometry("400x300")

    tk.Label(root, text="Username:").pack()
    username_entry = tk.Entry(root)
    username_entry.pack()

    tk.Label(root, text="Password:").pack()
    password_entry = tk.Entry(root, show="*")
    password_entry.pack()

    def handle_login():
        username = username_entry.get()
        password = password_entry.get()
        response = client.login_user(username, password)
        if response == "SUCCESS":
            messagebox.showinfo("Success", "Login Successful")
            root.destroy()
            Home_client.home_GUI(client)

        else:
            messagebox.showerror("Error", response)

    tk.Button(root, text="Login", command=handle_login).pack(pady=10)
    root.mainloop()


if __name__ == "__main__":
    login_gui()
