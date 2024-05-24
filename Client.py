import socket
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
import sys
import os
from utils import message_handler

client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client_socket.connect(('localhost', 8000))

PU_server = client_socket.recv(2048)
PU_server = serialization.load_pem_public_key(PU_server, backend=default_backend())

key = os.urandom(32)
encrypted_key = PU_server.encrypt(
    key,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)

client_socket.sendall(encrypted_key)
print('Encrypted key sent to the server')
shared_key = key

choice = input('Enter (r) for register or (l) for login: ')
encrypted_choice = message_handler(choice, shared_key)
client_socket.sendall(encrypted_choice)

username = input('Username: ')
password = input('Password: ')
encrypted_username = message_handler(username, shared_key)
encrypted_password = message_handler(password, shared_key)

client_socket.sendall(encrypted_username)
print('Encrypted username sent to the server')
client_socket.sendall(encrypted_password)
print('Encrypted password sent to the server')
enc_confo = client_socket.recv(2048)
confo = message_handler(enc_confo, shared_key)
print('Received Confirmation:', confo)
isAuthenticated = confo not in ['User already exist.', 'Invalid username or password.']

if isAuthenticated:
    while True:
        message = input('Enter a message to send to the server:')
        send_msg = message_handler(message, shared_key)
        client_socket.sendall(send_msg)

        if message == 'exit':
            client_socket.close()
            break

        encrypted_server_message = client_socket.recv(1024)
        server_message = message_handler(encrypted_server_message, shared_key)
        print('Received from server:', server_message)
