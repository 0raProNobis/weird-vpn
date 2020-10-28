import os
import sys
import uuid
import socket
import pickle
import argparse

from packet import Command, Packet
from cryptohelper import RSAHelper, AESHelper, ECHelper


class ClientMap():

    def __init__(self, other: Client):
        self.isowner = other.isowner
        self.owneruuid = other.owneruuid
        self.serveruuid = other.serveruuid
        self.uuid = other.uuid
        self.rsa = self.__rsacrypt.dumpprivkey()
        self.aes = other.aes



class Client():
    isowner = False
    __rsacrypt: RSAHelper = None
    __aesmapping = {}
    __rsapem = None

    def __init__(self, server_host="127.0.0.1", server_port=9999):
        self.server_host = "127.0.0.1"
        self.port = 9999
        self._filepath = './client.pkl'
        self.__client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        if os.path.exists(self._filepath):
            try:
                self.load()
            except EOFError:
                self.setdefault()
        else:
            self.setdefault()

    def setdefault(self):
        self.isowner = False
        self.owneruuid = None
        self.serveruuid = uuid.UUID(bytes=b'\x00'*16)
        self.uuid = uuid.uuid4()
        self.__rsacrypt = RSAHelper()
        self.__rsacrypt.generateKeys()

    def load(self):
        with open(self._filepath, 'rb') as fle:
            other = pickle.load(fle)
        self.isowner = other.isowner
        self.owneruuid = other.owneruuid
        self.serveruuid = other.serveruuid
        self.uuid = other.uuid
        self.__rsacrypt = RSAHelper()
        self.__rsacrypt.loadfromprivpem(other.rsa)
        self.aes = other.aes

    def save(self):
        mapping = ClientMap(self)
        with open(self._filepath, 'wb') as fle:
            pickle.dump(mapping, fle)
        
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
        self.save()

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

    def __del__(self):
        self.save()