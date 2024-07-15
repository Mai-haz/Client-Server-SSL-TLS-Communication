from flask import Flask, request, render_template
from flask import redirect, url_for
import requests
from flask import jsonify 
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
import os
from flask import Flask, request, render_template
from flask import redirect, url_for
import os
import sys
import ssl
import requests
from flask import Flask, request, render_template
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives import serialization
import os
import requests
import requests
from cryptography.hazmat.primitives import serialization
#from cryptography.hazmat.primitives.asymmetric import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric import utils
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric import utils
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives import serialization
from flask import Flask, request, render_template
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import padding
import requests
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
import base64

app = Flask(__name__)

global key
key = 10
global Chosenmethod
Chosenmethod=""
# Generate server's Diffie-Hellman private key
"""
server_parameters = dh.generate_parameters(generator=2, key_size=2048)
server_private_key = server_parameters.generate_private_key()
server_public_key = server_private_key.public_key()
server_public_key_bytes = server_public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo,
)
"""
@app.route('/')
def home():
    return render_template('server.html')
print("before")

@app.route('/receive_hello', methods=['POST'])
def receive_hello():
    print("Client said hello")
    #return server_public_key_bytes
    return "HELLO"


@app.route('/process', methods=['POST'])
def process():
    global key
    key = request.form['key']
    if key:
        return f'You entered the key: {key}'
    
print("i got here")

@app.route('/receive_chosen_method', methods=['GET', 'POST'])
def receive_chosen_method():
    global shared_key
    global client_shared_key
    global server_public_key
    global serialized_server_public_key
    keys_directory = 'Serverkeys'
    os.makedirs(keys_directory, exist_ok=True)

    data = request.get_json()
    Chosenmethod = data['method']
    key = data['key']
    print("the chosen method was ", Chosenmethod)
    print("the key you entered was",key)
    # Process the chosen method and key as needed
    if Chosenmethod=="AES" or Chosenmethod=="SHA256":
        def generate_dh_parameters():
            parameters = dh.generate_parameters(generator=2, key_size=2048, backend=default_backend())
            private_key = parameters.generate_private_key()
            public_key = private_key.public_key()
            return private_key, public_key

        def serialize_public_key(public_key):
            return public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        server_private_key, server_public_key = generate_dh_parameters()
        serialized_server_public_key = server_public_key.public_bytes(encoding=serialization.Encoding.PEM,format=serialization.PublicFormat.SubjectPublicKeyInfo)
        # Send the server's key back to the client
        response_data = {'key':serialized_server_public_key }
        print("shared key from AES",serialized_server_public_key)
        #return jsonify(response_data)
        
        

        server_public_key_path = os.path.join(keys_directory, 'server_public_key.pem')
        with open(server_public_key_path, 'wb') as key_file:
            key_file.write(serialized_server_public_key)

        response_data = {'key': server_public_key_path}
        print("shared key from AES", serialized_server_public_key)
        

        return jsonify(response_data)

    
    if Chosenmethod =="RSA":
        def generate_rsa_key_pair():
            private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
            )
            public_key = private_key.public_key()
            return private_key, public_key

        def serialize_public_key(public_key):
            return public_key.public_bytes(
            encoding=serialization.Encoding.PEM,format=serialization.PublicFormat.SubjectPublicKeyInfo)
        server_private_key, server_public_key = generate_rsa_key_pair()
        serialized_server_public_key = serialize_public_key(server_public_key)

        response_data = {'key':serialized_server_public_key }
        print("shared key from RSA",serialized_server_public_key)
        #return jsonify(response_data)
       
        server_public_key_path = os.path.join(keys_directory, 'rsa_server_public_key.pem')
        with open(server_public_key_path, 'wb') as key_file:
            key_file.write(serialized_server_public_key)
        return jsonify({'key': serialized_server_public_key.decode('utf-8')})
    
@app.route('/recieve_encrypted_message', methods=['GET', 'POST'])
def recieve_encrypted_message():
    if Chosenmethod=="AES":
        shared_key_file_path =  r"C:\User"
        with open(shared_key_file_path, 'rb') as key_file:
            shared_key_bytes = key_file.read()

        # Convert the shared key bytes back to an integer
        shared_key = int.from_bytes(shared_key_bytes, byteorder='big')
        shared_key_bytes = shared_key.to_bytes((shared_key.bit_length() + 7) // 8, byteorder='big')

        # Derive a symmetric key using PBKDF2
        kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        iterations=100000,  # Adjust the number of iterations as needed
        salt=b'some_salt',  # Change the salt to something unique and random
        length=32  # AES-256 key size
        )
        symmetric_key = kdf.derive(shared_key_bytes)
        user_key=symmetric_key
        if len(user_key) not in (16, 24, 32):
            print("length issue")
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

        # Decrypt the message

        with open(r'C:\Users\)', 'rb') as file:
            encrypted_message = file.read()

        decrypted_message = cipher_suite.decrypt(encrypted_message)
        print("Decrypted Message:", decrypted_message.decode())

if __name__ == '__main__':
    #app.run(ssl_context=('C:\Users\mayha\OneDrive\Desktop\A2-info\cert.pem', 'C:\Users\mayha\OneDrive\Desktop\A2-info\key.pem'))
    app.run(debug=True ,port = 5001 , ssl_context=(r'C:\Users', r'C:\Users'))

    print("the chosen method was ", Chosenmethod)
    print("the key you entered was",key)
    print("shared key from AES",serialized_server_public_key)
    print("shared key from RSA",serialized_server_public_key)





