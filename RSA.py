from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

# Get input from the user
message = input("Enter the message to be encrypted: ")

# Generate an RSA key pair (you can also load an existing key pair)
key = RSA.generate(2048)  # You can adjust the key size (e.g., 2048 bits)

# Create an RSA cipher object for encryption
cipher = PKCS1_OAEP.new(key.publickey())

# Encrypt the message
encrypted_message = cipher.encrypt(message.encode())

print("Encrypted Message:", encrypted_message)

# Create a new RSA cipher object for decryption
decipher = PKCS1_OAEP.new(key)

# Decrypt the message
decrypted_message = decipher.decrypt(encrypted_message)

print("Decrypted Message:", decrypted_message.decode())
