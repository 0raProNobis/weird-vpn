import os
import sys
import uuid
import socket
import pickle
import argparse
import builtins

from packet import Command, Packet
from cryptohelper import RSAHelper, AESHelper, ECHelper


class ClientMap():

    def __init__(self, other):
        self.isowner = other.isowner
        self.owneruuid = other.owneruuid
        self.serveruuid = other.serveruuid
        self.uuid = other.uuid
        self.rsa = other.dumprsakey()
        self.aes = other.dumpaes()
        self.orphanedkey = other.orphanedkey
        self.orphanedclient = other.orphanedclient
        if other.serverkey:
            self.serverkey = RSAHelper.pub2pem(other.serverkey)
        else:
            self.serverkey = None


class Client():
    isowner = False
    __rsacrypt: RSAHelper = None
    __aesmapping = {}
    orphanedkey = None
    orphanedclient = None

    def __init__(self, server_host="127.0.0.1", server_port=9999, filepath='./client.pkl'):
        self.server_host = "127.0.0.1"
        self.port = 9999
        self.filepath = filepath
        self.__client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        if os.path.exists(self.filepath):
            try:
                self.load()
            except EOFError:
                self.setdefault()
        else:
            self.setdefault()

    def sharekey(self):
        if self.isowner and self.orphanedkey:
            raise Exception()
        ec = ECHelper()
        ec.generatekeys()
        print(f'Your key is:\n{ec.pubkey}')
        pem = input("What is the other client's key? ") + '\n'
        pem += input() + '\n'
        pem += input() + '\n'
        pem += input() + '\n'
        pem += input() + '\n'
        ec.generatesharedkey(pem.encode())
        if self.isowner:
            self.orphanedkey = ec.derivedkey
        else:
            self.__aesmapping[self.owneruuid] = ec.derivedkey

    def dumpaes(self):
        return self.__aesmapping

    def dumprsakey(self):
        return self.__rsacrypt.dumpprivkey()

    def setdefault(self):
        self.isowner = False
        self.owneruuid = None
        self.serveruuid = uuid.UUID(bytes=b'\x00'*16)
        self.uuid = uuid.uuid4()
        self.__rsacrypt = RSAHelper()
        self.__rsacrypt.generateKeys()
        self.serverkey = None

    def load(self):
        with open(self.filepath, 'rb') as fle:
            other = pickle.load(fle)
        self.isowner = other.isowner
        self.owneruuid = other.owneruuid
        self.serveruuid = other.serveruuid
        self.uuid = other.uuid
        self.__rsacrypt = RSAHelper()
        self.__rsacrypt.loadfromprivpem(other.rsa)
        self.__aesmapping = other.aes
        self.serverkey = self.__rsacrypt.pem2key(other.serverkey)
        self.orphanedkey = other.orphanedkey
        self.orphanedclient = other.orphanedclient

    def save(self):
        mapping = ClientMap(self)
        with open(self.filepath, 'wb') as fle:
            pickle.dump(mapping, fle)

    def send(self, packet: Packet, server=False):
        self.__client.connect((self.server_host, self.port))
        for p in packet.build(encrypt=(packet.command != Command.REGISTER), server=server):
            self.__client.send(p)
        resp = self.recv(encrypt=(packet.command != Command.REGISTER), server=server)
        return resp

    def recv(self, encrypt=True, server=False):
        d = self.__client.recv(512)
        packet = Packet()
        if encrypt:
            packet.rsa = self.__rsacrypt
            msg = packet.decrypt(d[256:])
            self.__rsacrypt.verify(msg, d[:256], self.serverkey)
            packet.from_bytes(msg)
            if packet.sender != self.serveruuid:
                packet.aes = self.__aesmapping[packet.sender]
                packet.decrypt_payload()
        else:
            packet.from_bytes(d)
            if packet.command == Command.SHAREPUB:
                d = self.__client.recv(21)
                packet.payload = packet.payload + d
        return packet

    def buildpacket(self, receiver):
        p = Packet()
        p.sender = self.uuid
        p.receiver = receiver
        p.rsa = self.__rsacrypt
        p.pubkey = self.serverkey
        if receiver != self.serveruuid:
            p.aes = self.__aesmapping[receiver]
        return p

    def addclient(self):
        p = self.buildpacket(self.serveruuid)
        p.command = Command.ADDCLIENT
        resp = self.send(p, server=True)
        if resp.command == Command.ACK:
            key = resp.payload[:6].decode()
            print(f"Server returned key: {key}")
        elif resp.command == Command.FAIL:
            print("Failed")

    def register(self):
        key = input("What is the registration key the server provided? ")
        while len(key) != 6:
            key = '0' + key
        p = self.buildpacket(self.serveruuid)
        p.command = Command.REGISTER
        p.payload = key.encode() + self.__rsacrypt.pubkey2pem()
        resp = self.send(p)
        if resp.command == Command.SHAREPUB:
            self.serveruuid = resp.sender
            self.owneruuid = uuid.UUID(bytes=resp.payload[:16])
            self.isowner = self.owneruuid == self.uuid
            self.serverkey = self.__rsacrypt.pem2key(resp.payload[16:])

        elif resp.command == Command.FAIL:
            pass
        else:
            pass

    def transmit(self, recipient, message: str):
        p = self.buildpacket(uuid.UUID(recipient))
        p.command = Command.TRANSMIT
        p.receiver = uuid.UUID(recipient)
        p.payload = message.encode()
        resp = self.send(p)
        if resp.command == Command.ACK:
            print("Success")
        elif resp.command == Command.FAIL:
            print("Fail")
        else:
            pass

    def receive(self):
        p = self.buildpacket(self.serveruuid)
        p.command = Command.RECEIVE
        resp = self.send(p, server=True)
        if resp.command == Command.QUERYMAILBOX:
            count = int.from_bytes(resp.payload, 'big')
            for i in range(count):
                resp = self.recv(server=True)
                if resp.command == Command.SHAREKEY and self.orphanedkey is not None:
                    self.__aesmapping[uuid.UUID(bytes=resp.payload)] = self.orphanedkey
                    self.orphanedkey = None
                elif resp.command == Command.SHAREKEY:
                    self.orphanedclient = uuid.UUID(resp.payload.decode())
                else:
                    print(f"Server command: {resp.command}")
                    print(f"Server payload: {resp.payload.decode()}")

    def __del__(self):
        self.save()