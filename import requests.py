import requests
import base64

# Sample public key for the server
server_public_key = {
    'n': 143,  # Replace with the server's public modulus (typically a large prime number)
    'e': 7    # Replace with the server's public exponent (typically a small prime number)
}

# User's entered message (replace with actual user input from the HTML form)
message = input("Enter your message: ")

# User's chosen encryption method (replace with actual user choice from the HTML form)
encryption_method = "RSA"

# Function to encrypt a message using a simple RSA-like algorithm (for educational purposes)
def rsa_like_encryption(public_key, message):
    encrypted_message = ""
    for char in message:
        char_code = ord(char)
        encrypted_char_code = pow(char_code, public_key['e'], public_key['n'])
        encrypted_message += str(encrypted_char_code) + ' '

    return encrypted_message.strip()

# Check if the user has chosen RSA encryption
if encryption_method == "RSA":
    # Encrypt the user's entered message using the server's public key
    encrypted_message = rsa_like_encryption(server_public_key, message)

    # Prepare the data to send to the server
    data = {
        'encryption_method': 'RSA',
        'encrypted_message': encrypted_message
    }

    # Send the encrypted message to the server (replace 'http://server-url/send_message' with the actual server endpoint)
    response = requests.post('http://server-url/send_message', json=data)

    # Print the server's response
    print(response.json())
else:
    # Handle other encryption methods if needed
    pass



import random

# Function to check if a number is prime
def is_prime(num):
    if num <= 1:
        return False
    if num <= 3:
        return True
    if num % 2 == 0 or num % 3 == 0:
        return False
    i = 5
    while i * i <= num:
        if num % i == 0 or num % (i + 2) == 0:
            return False
        i += 6
    return True

# Function to find the greatest common divisor
def gcd(a, b):
    while b:
        a, b = b, a % b
    return a

# Function to generate a random prime number
def generate_prime(bits):
    while True:
        num = random.getrandbits(bits)
        if is_prime(num):
            return num

# Function to generate RSA key pair
def generate_rsa_key_pair():
    # Choose two large prime numbers
    p = generate_prime(1024)
    q = generate_prime(1024)

    # Compute n (modulus)
    n = p * q

    # Compute the totient (phi) of n
    phi = (p - 1) * (q - 1)

    # Choose e (public exponent)
    e = 65537  # Commonly used value for e

    # Compute d (private exponent)
    d = 0
    while True:
        d += 1
        if (d * e) % phi == 1:
            break

    public_key = (e, n)
    private_key = (d, n)
    return public_key, private_key

# Encrypt a message using the public key
def encrypt(message, public_key):
    e, n = public_key
    encrypted_message = [pow(ord(char), e, n) for char in message]
    return encrypted_message

# Decrypt a message using the private key
def decrypt(encrypted_message, private_key):
    d, n = private_key
    decrypted_message = [chr(pow(char, d, n)) for char in encrypted_message]
    return ''.join(decrypted_message)

# Example usage
message = "Hello, RSA!"
public_key, private_key = generate_rsa_key_pair()
encrypted_message = encrypt(message, public_key)
decrypted_message = decrypt(encrypted_message, private_key)

print(f"Original message: {message}")
print(f"Encrypted message: {encrypted_message}")
print(f"Decrypted message: {decrypted_message}")
