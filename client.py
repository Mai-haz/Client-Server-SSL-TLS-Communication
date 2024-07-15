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
    Chosenmethod="AES"
    global key

    global shared_key
    global client_shared_key
    global server_public_key
    keys_directory = 'keys'
    os.makedirs(keys_directory, exist_ok=True)
    # For saving client's public key
    client_public_key_path = os.path.join(keys_directory, 'client_public_key.pem')

    # For saving server's public key
    server_public_key_path = os.path.join(keys_directory, 'server_public_key.pem')


    def deserialize_public_key(serialized_key_path):
        with open(serialized_key_path, 'rb') as key_file:
            key_data = key_file.read()
        return serialization.load_pem_public_key(key_data, backend=default_backend())



    def generate_dh_key_pair():
        parameters = dh.generate_parameters(generator=2, key_size=2048, backend=default_backend())
        private_key = parameters.generate_private_key()
        public_key = private_key.public_key()
        return private_key, public_key

    def generate_rsa_key_pair():
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        public_key = private_key.public_key()
        return private_key, public_key

    if Chosenmethod in ["AES", "SHA256"]:
        client_private_key, client_public_key = generate_dh_key_pair()
        serialized_client_public_key = client_public_key.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo)
        # After generating client's key
        with open(client_public_key_path, 'wb') as key_file:
            key_file.write(serialized_client_public_key)

        # Send the chosen method and key to the server
        #data = {'method': Chosenmethod, 'key': serialized_client_public_key}
        #response = requests.post('https://localhost:5001/receive_chosen_method', json=data, verify=False)
        data = {'method': Chosenmethod, 'key': serialized_client_public_key.decode('utf-8')}
        response = requests.post('https://localhost:5001/receive_chosen_method', json=data, verify=False)

        if response.status_code == 200:
            server_response = response.json()
            server_key_path = os.path.join(keys_directory, 'server_public_key_received.pem')

            # Write the received key to a file
            #with open(server_key_path, 'wb') as key_file:
            with open(server_key_path, 'wb') as key_file:
                key_file.write(server_response['key'].encode('utf-8'))

            # Read the key from the file
            server_key_path=r"C:"
            server_public_key = deserialize_public_key(server_key_path)

            # Perform the key exchange
            #shared_key = client_private_key.exchange(server_public_key)
            try:
                shared_key = client_private_key.exchange(server_public_key)
            except Exception as e:
                print(f"Error computing shared key: {e}")
                raise  # Raising the exception again for more detailed traceback

            shared_key_bytes = shared_key.to_bytes((shared_key.bit_length() + 7) // 8, byteorder='big')

            # Write the shared key to a file
            shared_key_file_path = r"C:"
            with open(shared_key_file_path, 'wb') as key_file:
                key_file.write(shared_key_bytes)   

            print(f"Server key from Diffie-Hellman is: {server_public_key}")
            return f"Chosen method: {Chosenmethod}, Server key: {server_public_key}"
        else:
            return "Failed to send the chosen method and key to the server"
    
    elif Chosenmethod == "RSA":
        client_private_key, client_public_key = generate_rsa_key_pair()
        serialized_client_public_key = client_public_key.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo)

        # Save the client's public key to a file
        client_key_path = os.path.join(keys_directory, 'rsa_client_public_key.pem')
        with open(client_key_path, 'wb') as key_file:
            key_file.write(serialized_client_public_key)

        # Send the client's public key to the server
        data = {'method': Chosenmethod, 'key': serialized_client_public_key.decode('utf-8')}
        response = requests.post('https://localhost:5001/receive_chosen_method', json=data, verify=False)

        if response.status_code == 200:
            server_response = response.json()
            server_key_path = os.path.join(keys_directory, 'rsa_server_public_key.pem')
            with open(server_key_path, 'wb') as key_file:
                key_file.write(server_response['key'])


            # Read the server's public key from the file
            server_key_path=r"C:"
            server_public_key = deserialize_public_key(server_key_path)
            print("the server key from RSA is ", server_public_key)

            return f"Chosen method: {Chosenmethod}, Server key from RSA: {server_public_key}"
        else:
            return "Failed to send the chosen method and key to the server"

        
    # Add a default return statement to handle other cases
    return "Invalid Chosenmethod"

@app.route('/send_encrypted_message', methods=['GET', 'POST'])
def send_encrypted_message():
    if Chosenmethod=="AES":
        shared_key_file_path =  r"C:"
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
        #key = base64.urlsafe_b64encode(kdf.derive(user_key.encode()))
        key = base64.urlsafe_b64encode(kdf.derive(user_key.encode('utf-8')))

        # Create a Fernet cipher with the derived key
        cipher_suite = Fernet(key)

        # Encrypt the message
        encrypted_message = cipher_suite.encrypt(message.encode())
        encrypted_message_file_path = r"C:"
        with open(encrypted_message_file_path , 'wb') as key_file:
                key_file.write(encrypted_message)  

        print("Encrypted Message:", encrypted_message.decode())

    """
    if Chosenmethod=="SHA256":
        
    if Chosenmethod="RSA":
    """






if __name__ == '__main__':
    ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    #ssl_context.load_cert_chain(certfile='C:\Users\mayha\OneDrive\Desktop\7thSemester\IS\A2-info\cert.pem', keyfile='C:\Users\mayha\OneDrive\Desktop\7thSemester\IS\A2-info\key.pem')
    ssl_context.load_cert_chain(certfile=r'C:', keyfile=r'C:')

    app.run(debug=True, port = 5000 , ssl_context=ssl_context)
    print("hi m")
    print("Received Message:", message)
    if(Chosenmethod=='AES'):
        print("Dear user you chose AES")
    print("the chosen method is",Chosenmethod)
    print("the key you chose is ",key)
    print(f"Server key from deffie helman is  : {server_public_key}")
    print("the server key from rsa is ",server_public_key) 
