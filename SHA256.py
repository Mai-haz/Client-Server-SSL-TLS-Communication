import hashlib

# Get input from the user
message = input("Enter the message to be hashed: ")
key = input("Enter the key (optional): ")

# Combine the message and key (if provided)
if key:
    message += key

# Calculate the SHA-256 hash
hash_object = hashlib.sha256(message.encode())
hashed_message = hash_object.hexdigest()

print(f"The SHA-256 hash of the message is: {hashed_message}")
