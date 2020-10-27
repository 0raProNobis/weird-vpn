import os
import sys
import socket
import argparse
from cryptohelper import RSAHelper, AESHelper, ECHelper


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

    sender = uuid.uuid4() # set to random UUID, should be overwritten
    receiver = uuid.uuid4() # set to random UUID, should be overwritten
    payload = b''
    max_size = 256 # maximum number for two byte integer, which we use for the length field
    command = Command.TRANSMIT
    aes: AESHelper = None
    rsa: RSAHelper = None

    def __init__(self):
        pass

    def trim_payload(self):
        pass

    def from_bytes(self, data):
        print("from_bytes")
        self.sender = uuid.UUID(bytes=data[:16])
        self.receiver = uuid.UUID(bytes=data[16:32])
        self.command = Command(int.from_bytes(data[32:33], 'big'))
        self.payload = data[33:]
        if self.command in [Command.ADDCLIENT, Command.REGISTER,
                            Command.QUERYCLIENTS, Command.QUERYMAILBOX]:
            self.trim_payload()

    def encrypt_key(self):
        pass

    def encrypt_payload(self, data):
        # TODO: encrypt self.payload here
        return data

    def decrypt_payload(self):
        pass

    def decrypt(self):
        pass

    def encrypt(self):
        pass

    def build(self, server=False, encrypt=True):
        # Sender and receiver should be 128 bit UUIDs
        meta_length = 33

        remaining_data = self.payload
        remaining_size = self.max_size - meta_length
        base_packet = b''
        base_packet += self.sender.bytes
        base_packet += self.receiver.bytes
        base_packet += self.command.value.to_bytes(1, 'big') # Server commands
        if self.command != Command.REGISTER:
            packet = basepacket + remaining_data
            remaining_data = 0
            yield packet
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
                packet += self.encrypt_key(packet_data)
            elif encrypt and not server:
                packet += self.encrypt_payload(packet_data)
            else:
                packet += packet_data

            if encrypt:
                packet = self.encrypt(packet)
            yield packet
###

class Client():
    isowner = False
    __rsacrypt = None
    __aesmapping = {}

    def __init__(self, server_host="127.0.0.1", server_port=9999):
        self.server_host = "127.0.0.1"
        self.port = 9999

        self.isowner = False
        self.owneruuid = None
        self.serveruuid = uuid.UUID(bytes=b'\x00'*16)
        self.__client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.uuid = uuid.uuid4()
        self.config = self.load_config('oddball.config')
        self.rsa = RSAHelper()
        self.rsa.generateKeys()

    def load_config(self, flepath):
        pass
        
    def checkMessages(self):
        #checks for messages on server, return int #n of messages
        pass
        
    def fetchMessages(self):
        #gets the messages from the server
        pass

    def send(self, packet: Packet):
        self.__client.connect((self.server_host, self.port))
        for p in packet.build(encrypt=(packet.command != Command.REGISTER)):
            self.__client.send(p)
        resp = self.recv(encrypt=(packet.command != Command.REGISTER))
        return resp

    def recv(self, encrypt=True):
        d = self.__client.recv(256)
        packet = Packet()
        if encrypt:
            pass
        else:
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
        while len(key) != 6:
            key = '0' + key
        p = self.buildpacket()
        p.command = Command.REGISTER
        p.receiver = self.serveruuid
        p.payload = key.encode() + self.rsa.pubkey2pem()
        print(key.encode())
        print(self.rsa.pubkey2pem())
        print(len(p.payload))
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
