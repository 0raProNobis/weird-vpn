import os
import sys
import uuid
import socket
import argparse

from cryptohelper import RSAHelper, AESHelper, ECHelper
from packet import Command, Packet


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




