import sys
import os
import socket
import argparse


### From common/packet.py
import uuid
import enum


class Command(enum.Enum):
    TRANSMIT = 0
    RECEIVE = 1
    ACK = 2
    ADDCLIENT = 3
    REGISTER = 4
    SHAREKEY = 5
    QUERYCLIENTS = 6
    QUERYMAILBOX = 7
    FAIL = 8


class Packet():

    sender = uuid.UUID() # set to random UUID, should be overwritten
    receiver = uuid.UUID() # set to random UUID, should be overwritten
    payload = b''
    max_size = 65536 # maximum number for two byte integer, which we use for the length field
    command = Command.TRANSMIT
    skey = None
    akey_pub = None
    akey_priv = None
    ekey_pub = None
    ekey_priv = None


    def __init__(self):
        pass

    def trim_payload(self):
        pass

    def from_bytes(self, data):
        self.sender = uuid.UUID(bytes=data[:17])
        self.receiver = uuid.UUID(bytes=data[17:33])
        self.command = Command(int(data[33:34]))
        self.payload = data[34:]
        if self.command in [Command.ADDCLIENT, Command.REGISTER,
                            Command.QUERYCLIENTS, Command.QUERYMAILBOX]:
            self.trim_payload()

    def encrypt_key(self):
        pass

    def encrypt_payload(self, data, key):
        # TODO: encrypt self.payload here
        pass

    def decrypt_payload(self):
        pass

    def decrypt(self):
        pass

    def encrypt(self):
        pass

    def build(self):
        # Sender and receiver should be 128 bit UUIDs
        meta_length = 256

        remaining_data = self.payload
        remaining_size = self.max_size - meta_length
        base_packet = b''
        base_packet += self.sender.bytes()
        base_packet += self.receiver.bytes()
        base_packet += self.command.to_bytes(1) # Server commands
        while len(remaining_data) != 0:
            if len(remaining_data) > remaining_size:
                packet_data = remaining_data[:remaining_size]
                remaining_data = remaining_data[remaining_size:]
            else:
                packet_data = remaining_data + (b'0' * remaining_size)
                remaining_data = b''

            # Create header information for server
            packet = base_packet

            # Add payload data
            if self.command == Command.SHAREKEY:
                packet_data = self.encrypt_key()
            else:
                packet_data = self.encrypt_payload()
            packet += packet_data

            # TODO: whole packet encryption here
            yield packet
###

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
        self.owner = False
        self.serveruuid = uuid.UUID(int=0)
        self.__client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.uuid = uuid.UUID()
        self.config = self.load_config('oddball.config')

    def load_config(self, flepath):
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






    def send(self, packet: Packet):
        self.__client.connect((self.server_host, self.port))
        for p in packet.build():
            self.__client.client.send(p)
        resp = self.recv()
        return resp

    def recv(self):
        self.__client.connect((self.server_host, self.port))
        d = self.__client.recv(65536)
        packet = Packet()
        packet.from_bytes(d)
        return packet

    def buildpacket(self):
        p = Packet()
        p.sender = self.uuid
        return p

    def addclient(self):
        pass

    def register(self):
        key = input("What is the registration key the server provided? ")
        p = self.buildpacket()
        p.command = Command.REGISTER
        p.receiver = self.serveruuid
        p.payload = key.to_bytes()
        resp = self.send(p)
        if resp.command == Command.ACK:
            self.serveruuid = resp.sender
        elif resp.command == Command.FAIL:
            pass
        else:
            pass

    def transmit(self, recipient, message: str):
        message = message.to_bytes()
        p = self.buildpacket()
        p.command = Command.TRANSMIT
        p.receiver = uuid.UUID(int=recipient)
        p.payload = message.to_bytes()
        resp = self.send(p)
        if resp.command == Command.ACK:
            print("Success")
        elif resp.command == Command.FAIL:
            print("Fail")
        else:
            pass

    def receive(self):
        p = self.buildpacket()
        p.command = Command.RECEIVE
        '''
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
        encryptor = cipher.encryptor()
        cipherText = encryptor.update(message) + encryptor.finalize()
        ivAndCipherText = iv + cipherText
        return ivAndCipherText
        '''
        


        
    def decryptPayload(completePayload):
        key = 
        iv= completePayload[0:16]
        
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
        decryptor = cipher.decryptor()
        plainText = decryptor.update(completePayload) + decryptor.finalize()
        return plainText



parser = argparse.ArgumentParser(prog='', description="")
command_group = parser.add_mutually_exclusive_group(required=True)
parser.add_argument('address', type=str)
parser.add_argument('-p', '--port', type=int)
command_group.add_argument('-t', '--transmit', type=str)
command_group.add_argument('-r', '--receive', action='store_true')
command_group.add_argument('--addclient', action='store_true')
command_group.add_argument('--register', action='store_true')
parser.add_argument('-i', '--id', type=int, required=('-t' in sys.argv or '--transmit' in sys.argv))

args = parser.parse_args()

if args.port:
    client = Client(server_host=args.address, server_port=args.port)
else:
    client = Client(server_host=args.address)


if args.transmit:
    client.transmit(args.id, args.transmit)
elif args.receive:
    client.receive()
elif args.addclient:
    client.addclient()
else:
    client.register()
