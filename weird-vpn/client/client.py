import os
import socket

from ..common import packet

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import PublicFormat
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


class Client():
    isowner = False
    elliptic_key_private = None
    elliptic_key_shared = None

    def __init__(self, server_host="127.0.0.1", server_port=9999):
        self.server_host = "127.0.0.1"
        self.port = 9999
        self.__client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    def run(self):
        pass
    
    def sendMessage(server,port,recipient,message): #call made by the user to send a message. Should give us everything we need to to send a message.
        header = encryptHeader(recipient)
        completePayload = encryptPayload(message)
        #toDo send to server
        client.connect((target_host, target_port))
        client.send("message")
        
    def checkMessages:
        #checks for messages on server, return int #n of messages
        
    def fetchMessages:
        #gets the messages from the server
        
    def encryptHeader(recipient):
        #should generate and encrypt a header with RSA 
        #has a complemtary decryptHeader on the server
        #https://cryptography.io/en/latest/hazmat/primitives/asymmetric/rsa/
        return encryptedHeader
        
    def encryptPayload(message):
        key = 
        iv= os.urandom(16)


    def generate_elliptic_key(self):
        private_key = ec.generate_private_key(ec.SECP384R1(), default_backend())
        public_key = private_key.public_key()
        return private_key, public_key

    def share_symmetric_key(self, target):
        private_key, public_key = self.generate_elliptic_key()
        public_bytes = public_key.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
        public_str = server_bytes.decode()

        print(f"Your public key is:\n {public_str}\n\n")
        other_pem = input(f"What is the other device's public key? ")

        other_pem = serialization.load_pem_public_key(server_bytes_str.encode(), backend=default_backend())
        shared_key = server_private_key.exchange(
            ec.ECDH(), other_pem
        )
        if self.isowner:
            new_packet = packet.Packet()
        else:
            self.elliptic_key_shared = shared_key
            self.elliptic_key_private = private_key

    def process_key_share(self):
        pass






client.connect((target_host, target_port))

        cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
        encryptor = cipher.encryptor()
        cipherText = encryptor.update(message) + encryptor.finalize()
        ivAndCipherText = iv + cipherText
        return ivAndCipherText
        


        
    def decryptPayload(completePayload):
        key = 
        iv= completePayload[0:16]
        
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
        decryptor = cipher.decryptor()
        plainText = decryptor.update(completePayload) + decryptor.finalize()
        return plainText
        
