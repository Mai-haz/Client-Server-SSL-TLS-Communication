#client

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
from cryptography.hazmat.primitives.asymmetric import serialization
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
#from requests.packages.urllib3.exceptions import InsecureRequestWarning

#requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

app = Flask(__name__, template_folder='templates')

current_directory = os.path.dirname(os.path.abspath(__file__))
message_received = False
message = ""
encryption_method = ""
encrypt_message = ""
choice = ""
symmetricMethod = ""  # Define symmetricMethod at the global level
asymmetricMethod = ""  # Define asymmetricMethod at the global level
Chosenmethod = ""  # Define Chosenmethod at the global level
key = 10

client_private_key = dh.generate_parameters(generator=2, key_size=2048).generate_private_key()
client_public_key = client_private_key.public_key()
client_shared_key = None
@app.route('/')
def home():
    return render_template('user.html')
print("before")

@app.route('/say_hello_to_server', methods=['GET'])
def say_hello_to_server():
    # Send a "hello" message to the server
    response = requests.get('https://localhost:5001/receive_hello', data=client_public_key.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo), verify=False)
    
    if response.status_code == 200:
        print("Server said Hello")
        # Perform the key exchange
        response = requests.post('https://localhost:5001/perform_key_exchange', data=client_shared_key, verify=False)
        if response.status_code == 200:
            print("Key exchange successful")
        else:
            print("Key exchange failed")

        return "Server said Hello"
    else:
        return "Failed to send message to server"

 
@app.route('/encrypt', methods=['POST'])
def encrypt_message():
    global message  # Access the global message variable
    global message_received  # Access the global message_received variable
    global symmetricMethod
    global Chosenmethod
    global asymmetricMethod
    global key
    print("inside the function")
    message = request.form.get('message')
    encryption_method = request.form.get('encryptionMethod')
    
    if encryption_method == "symmetric":
        Chosenmethod = request.form.get('symmetricMethod')
    
    if encryption_method == "asymmetric":
        Chosenmethod = request.form.get('asymmetricMethod')

    key = request.form.get('key')
    print("Chosen method is", Chosenmethod)
    print("Received Message mayhan:", message)  # Print message within the function
    print("Encryption Method:", encryption_method)

    message_received = True  # Set the flag to indicate a message has been received
    if message_received:
        return "Message received and logged."

    return redirect(url_for('send_chosen_method'))
print("i got here")

@app.route('/send_chosen_method', methods=['GET', 'POST'])
def send_chosen_method():
    global Chosenmethod
    global key
    
    # Send the chosen method and key to the server
    data = {'method': Chosenmethod, 'key': key}
    response = requests.post('https://localhost:5001/receive_chosen_method', json=data, verify=False)
    
    if response.status_code == 200:
        server_response = response.json()
        server_key = server_response['key']
        print(f"Server key: {server_key}")
        return f"Chosen method: {Chosenmethod}, Server key: {server_key}"
    else:
        return "Failed to send the chosen method and key to the server"

print("i got out")
@app.route('/perform_key_exchange', methods=['POST'])
def perform_key_exchange():
    server_public_key_bytes = request.data
    server_public_key = serialization.load_pem_public_key(server_public_key_bytes)
    global client_shared_key
    client_shared_key = client_private_key.exchange(server_public_key)
    return "Key exchange successful."

@app.route('/send_shared_key', methods=['GET'])
def send_shared_key():
    if client_shared_key:
        shared_key_bytes = client_shared_key.to_bytes()
        return shared_key_bytes
    else:
        return "Shared key is not available."
 #########################################################################################3   
# Load the server's public key
with open('server_public_key.pem', 'rb') as key_file:
    server_public_key_bytes = key_file.read()

server_public_key = serialization.load_pem_public_key(server_public_key_bytes)

# Send a "hello" message to the server to get the server's public key
response = requests.post('https://localhost:5001/receive_hello', data='hello', verify=False)
client_public_key_bytes = response.content

# Load the client's private key (make sure you have your private key in a file)
with open('client_private_key.pem', 'rb') as key_file:
    client_private_key = serialization.load_pem_private_key(key_file.read(), password=None)

# Perform the Diffie-Hellman key exchange
shared_key = client_private_key.exchange(server_public_key)
#AES
#RSA
#SHA256
###############################################################################
def send_encrypted_message(ciphertext):
    response = requests.post('https://localhost:5001/receive_encrypted_message', data=ciphertext, verify=False)
    return response.status_code == 200
#################################################################################
if __name__ == '__main__':
    ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ssl_context.load_cert_chain(certfile='C:\\U', keyfile='C:\\')
    app.run(debug=True, port = 5000 , ssl_context=ssl_context)
    print("hi mayhan")
    print("Received Message:", message)
    if(Chosenmethod=='AES'):
        print("Dear user you chose AES")
    print("the chosen method is",Chosenmethod)
    print("the key you chose is ",key)

