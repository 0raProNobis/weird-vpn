import os
import socket
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

class Client():

    def __init__(self, server_host="127.0.0.1", server_port=9999)
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
        
