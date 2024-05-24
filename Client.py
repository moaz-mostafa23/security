import socket
import threading
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
import os
from utils import message_handler
import tkinter as tk
from tkinter import scrolledtext, messagebox, simpledialog

class ChatClient:
    def __init__(self, master):
        self.master = master
        self.master.title("Encrypted Chat Application")
        self.master.geometry("600x400")
        self.setup_gui()
        self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.connect_to_server()

    def setup_gui(self):
        self.top_frame = tk.Frame(self.master)
        self.top_frame.pack(side=tk.TOP, fill=tk.X)

        self.chat_display = scrolledtext.ScrolledText(self.master, state='disabled', height=20, wrap=tk.WORD)
        self.chat_display.pack(padx=20, pady=10, fill=tk.BOTH, expand=True)

        self.bottom_frame = tk.Frame(self.master)
        self.bottom_frame.pack(side=tk.BOTTOM, fill=tk.X)

        self.message_entry = tk.Entry(self.bottom_frame, width=50)
        self.message_entry.pack(padx=20, pady=5, side=tk.LEFT, fill=tk.X, expand=True)
        self.message_entry.bind("<Return>", lambda event: self.send_message())

        self.send_button = tk.Button(self.bottom_frame, text="Send", command=self.send_message)
        self.send_button.pack(padx=20, pady=5, side=tk.RIGHT)

    def connect_to_server(self):
        try:
            self.client_socket.connect(('localhost', 8000))
            threading.Thread(target=self.receive_messages, daemon=True).start()
            self.setup_encryption()
        except Exception as e:
            messagebox.showerror("Connection Error", str(e))

    def setup_encryption(self):
        self.PU_server = self.client_socket.recv(2048)
        self.PU_server = serialization.load_pem_public_key(self.PU_server, backend=default_backend())
        self.key = os.urandom(32)
        encrypted_key = self.PU_server.encrypt(
            self.key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        self.client_socket.sendall(encrypted_key)
        print('Encrypted key sent to the server')

        self.login_or_register()

    def login_or_register(self):
        choice = simpledialog.askstring("Login/Register", "Enter 'r' to register or 'l' to login:")
        encrypted_choice = message_handler(choice, self.key)
        self.client_socket.sendall(encrypted_choice)

        username = simpledialog.askstring("Username", "Enter your username:")
        password = simpledialog.askstring("Password", "Enter your password:", show='*')
        encrypted_username = message_handler(username, self.key)
        encrypted_password = message_handler(password, self.key)

        self.client_socket.sendall(encrypted_username)
        print('Encrypted username sent to the server')
        self.client_socket.sendall(encrypted_password)
        print('Encrypted password sent to the server')
        enc_confo = self.client_socket.recv(2048)
        confo = message_handler(enc_confo, self.key)
        messagebox.showinfo("Confirmation", confo)
        self.isAuthenticated = confo not in ['User already exist.', 'Invalid username or password.']

    def send_message(self):
        message = self.message_entry.get()
        if message:
            send_msg = message_handler(message, self.key)
            self.client_socket.sendall(send_msg)
            self.display_message("You", message)
            self.message_entry.delete(0, tk.END)

    def receive_messages(self):
        while True:
            try:
                encrypted_message = self.client_socket.recv(1024)
                message = message_handler(encrypted_message, self.key)
                self.display_message("Server", message)
            except Exception as e:
                print("Error receiving message:", e)
                break

    def display_message(self, sender, message):
        self.chat_display.config(state='normal')
        self.chat_display.insert(tk.END, f"{sender}: {message}\n")
        self.chat_display.yview(tk.END)
        self.chat_display.config(state='disabled')

def main():
    root = tk.Tk()
    client = ChatClient(root)
    root.mainloop()

if __name__ == "__main__":
    main()
