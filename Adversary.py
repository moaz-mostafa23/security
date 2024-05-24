from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import base64
import os
from utils import hashPassword, verify_password, message_handler

class Adversary:
    def __init__(self, possible_passwords):
        self.possible_passwords = possible_passwords

    def listen(self, encrypted_password, encrypted_message):
        self.encrypted_password = encrypted_password
        self.encrypted_message = encrypted_message

    def guess_password(self):
        for password in self.possible_passwords:
            yield password

    def crack_password(self, encrypted_password):
        print("Attempting to crack password...")
        for password in self.guess_password():
            try:
                if verify_password(password, encrypted_password):
                    print(f"Cracked the password: {password}")
                    return password
            except Exception as e:
                print(f"Password guess '{password}' failed: {e}")
                continue
        return None

    def crack_message(self, shared_key, encrypted_message):
        print("Adversary is attempting to crack the message...")
        try:
            decrypted_message = message_handler(encrypted_message, shared_key)
            print(f"Cracked the message: {decrypted_message}")
            return decrypted_message
        except Exception as e:
            print(f"Failed to crack the message: {e}")
            return None

# Usage Example
if __name__ == "__main__":
    # Sample possible passwords
    possible_passwords = ['password1', 'password2', 'password3']

    # Hashing a sample password for simulation
    sample_password = 'password1'
    encrypted_password = hashPassword(sample_password)

    # Sample encrypted message (Assume this is what the adversary intercepted)
    sample_message = "Hello, this is a secret message."
    shared_key = os.urandom(32)  # Simulate a shared key
    encrypted_message = message_handler(sample_message, shared_key)  # Encrypt the message for simulation

    # Initialize the adversary
    adversary = Adversary(possible_passwords)

    # Adversary listens to the communication (encrypted password and message)
    adversary.listen(encrypted_password, encrypted_message)

    # Crack the password
    cracked_password = adversary.crack_password(encrypted_password)

    if cracked_password:
        # Derive the shared key using the cracked password
        salt = base64.b64decode(encrypted_password)[:16]  # Extract the salt from the first 16 bytes
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        shared_key = base64.urlsafe_b64encode(kdf.derive(cracked_password.encode()))

        # Crack the encrypted message
        decrypted_message = adversary.crack_message(shared_key, encrypted_message)

        if decrypted_message:
            print(f"Decrypted message: {decrypted_message}")
        else:
            print("Failed to decrypt the message.")
