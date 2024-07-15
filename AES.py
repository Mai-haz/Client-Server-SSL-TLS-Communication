from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64

# Get the user's message and key
message = input("Enter the message to encrypt: ")
user_key = input("Enter the encryption key (16, 24, or 32 characters): ")

# Ensure the key is the correct length (16, 24, or 32 bytes)
if len(user_key) not in (16, 24, 32):
    print("Key length must be 16, 24, or 32 bytes.")
else:
    # Create a salt (a random value) for key derivation
    salt = b'salt_123'  # You can use a different value or generate a random one

    # Use PBKDF2 to derive a valid Fernet key from the user's input
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        iterations=100000,  # You can adjust the number of iterations for desired security
        salt=salt,
        length=32  # 32 bytes for Fernet
    )
    key = base64.urlsafe_b64encode(kdf.derive(user_key.encode()))

    # Create a Fernet cipher with the derived key
    cipher_suite = Fernet(key)

    # Encrypt the message
    encrypted_message = cipher_suite.encrypt(message.encode())
    print("Encrypted Message:", encrypted_message.decode())
    
    #############################################################################################
    #decryption
    cipher_suite = Fernet(key)

    # Decrypt the message
    decrypted_message = cipher_suite.decrypt(encrypted_message)
    print("Decrypted Message:", decrypted_message.decode())
