from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.padding import PKCS7
from cryptography.hazmat.primitives import hashes
import binascii
import re

def message_handler(message, key: bytes):
    assert len(key) == 32, "Key must be 32 bytes long"
    cipher_obj = Cipher(algorithms.AES(key), modes.CBC(b"myinitialvector6"), backend=default_backend())

    if isinstance(message, bytes):
        message = decrypt(cipher_obj, message)
    else:
        message = bytes(message, encoding="utf-8")
        message = encrypt(cipher_obj, message)
    return message

def encrypt(cipher_obj, message):
    padder = PKCS7(256).padder()
    padded_message = padder.update(message) + padder.finalize()
    hashed_message = hash_message(padded_message)
    encryptor = cipher_obj.encryptor()
    cipher_text = encryptor.update(padded_message + hashed_message) + encryptor.finalize()
    return cipher_text

def decrypt(cipher_obj, message):
    decryptor = cipher_obj.decryptor()
    decrypted_data = decryptor.update(message) + decryptor.finalize()
    decrypted_padded_message = decrypted_data[:-32]
    decrypted_hash = decrypted_data[-32:]
    unpadder = PKCS7(256).unpadder()
    decrypted_message = unpadder.update(decrypted_padded_message) + unpadder.finalize()
    hashed_message = hash_message(decrypted_padded_message)
    assert decrypted_hash == hashed_message, "Hashes do not match"
    return decrypted_message.decode()

def hash_message(data: bytes):
    digest = hashes.Hash(hashes.SHA256())
    digest.update(data)
    return digest.finalize()

def hashPassword(password):
    password = paddMessage(password)
    digest = hashes.Hash(hashes.SHA256())
    digest.update(password)
    return binascii.b2a_base64(digest.finalize()).decode()

def verify_password(password, hashed_password):
    return hashed_password == hashPassword(password)

def paddMessage(message: str):
    if not isinstance(message, bytes):
        message = bytes(message, encoding="utf-8")
    padder = PKCS7(256).padder()
    return padder.update(message) + padder.finalize()
