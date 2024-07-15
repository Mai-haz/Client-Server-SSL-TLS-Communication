#Server
from flask import Flask, request, render_template
from flask import redirect, url_for
import requests
from flask import jsonify 
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives import serialization



app = Flask(__name__)

global key
key = 10
global chosen_method
chosen_method=""
# Generate server's Diffie-Hellman private key
server_parameters = dh.generate_parameters(generator=2, key_size=2048)
server_private_key = server_parameters.generate_private_key()
server_public_key = server_private_key.public_key()
server_public_key_bytes = server_public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo,
)

@app.route('/')
def home():
    return render_template('server.html')
print("before")

@app.route('/receive_hello', methods=['POST'])
def receive_hello():
    print("Client said hello")
    return server_public_key_bytes



@app.route('/process', methods=['POST'])
def process():
    global key
    key = request.form['key']
    if key:
        return f'You entered the key: {key}'
    
print("i got here")

@app.route('/receive_chosen_method', methods=['POST'])
def receive_chosen_method():
    data = request.get_json()
    chosen_method = data['method']
    key = data['key']
    
    # Process the chosen method and key as needed
    
    # Send the server's key back to the client
    server_key = 12345  # Replace with the actual server key
    response_data = {'key': server_key}
    
    return jsonify(response_data)

@app.route('/perform_key_exchange', methods=['POST'])
def perform_key_exchange():
    client_public_key_bytes = request.data
    client_public_key = serialization.load_pem_public_key(client_public_key_bytes)
    
    # Perform the Diffie-Hellman key exchange
    shared_key = server_private_key.exchange(client_public_key)
    
    # You can store the shared_key for later use
    
    return "Key exchange successful."


if __name__ == '__main__':
    
    app.run(debug=True ,port = 5001 , ssl_context=('C:\\', 'C:\\'))
    print("the chosen method was ", chosen_method)
    print("the key you entered was",key)


###############################################################################
from flask import Flask, request, render_template
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import serialization
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa

app = Flask(__name__)

@app.route('/')
def home():
    return render_template('server.html')

@app.route('/receive_encrypted_message', methods=['POST'])
def receive_encrypted_message():
    # Retrieve the encrypted message, encryption method, and signature from the client
    encrypted_message = request.data
    encryption_method = request.args.get('method')
    signature = request.args.get('signature')

    # Handle decryption based on the encryption method
    if encryption_method == 'RSA':
        # Decrypt the message using RSA
        plaintext_message = decrypt_message_with_rsa(encrypted_message)
    elif encryption_method == 'AES':
        # Decrypt the message using AES
        plaintext_message = decrypt_message_with_aes(encrypted_message)
    elif encryption_method == 'SHA256':
        # Verify and decrypt the message using SHA-256
        if verify_signature(encrypted_message, signature):
            plaintext_message = decrypt_message_with_sha256(encrypted_message)
        else:
            return 'Signature verification failed'
    else:
        return 'Unsupported encryption method'

    return 'Decrypted Message: ' + plaintext_message

def decrypt_message_with_rsa(encrypted_message):
    # Implement RSA decryption logic here
    # Return the decrypted message as a string
    return "Decrypted RSA Message"

def decrypt_message_with_aes(encrypted_message):
    # Implement AES decryption logic here
    # Return the decrypted message as a string
    return "Decrypted AES Message"

def verify_signature(encrypted_message, signature):
    # Implement SHA-256 signature verification logic here
    # Return True if the signature is valid, else return False
    return True

def decrypt_message_with_sha256(encrypted_message):
    # Implement SHA-256 decryption logic here
    # Return the decrypted message as a string
    return "Decrypted SHA-256 Message"

if __name__ == '__main__':
    app.run(debug=True, port=5001)


