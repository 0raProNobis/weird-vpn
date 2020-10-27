import time
import uuid
import socket
import random
import logging
import threading
from cryptohelper import RSAHelper

### From ..common/packet.py
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
    SHAREPUB = 9


class Packet():

    sender = uuid.uuid4() # set to random UUID, should be overwritten
    receiver = uuid.uuid4() # set to random UUID, should be overwritten
    payload = b''
    max_size = 256 # maximum number for two byte integer, which we use for the length field
    command = Command.TRANSMIT
    aes = None
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

    def encrypt_payload(self, data):
        # TODO: encrypt data here with AES
        return data

    def decrypt_payload(self, data):
        return data

    def decrypt(self, data, decryptpayload=True):
        data = self.rsa.decrypt(data)
        if decryptpayload:
            payload = data[33:]
            payload = self.decrypt_payload(payload)
            data = data[:33] + payload
        return data

    def encrypt(self, data):
        # TODO: encrypt whole packet with receiver's pub key
        return data

    def build(self, server=False, encrypt=True):
        # Sender and receiver should be 128 bit UUIDs
        meta_length = 33

        remaining_data = self.payload
        remaining_size = self.max_size - meta_length
        base_packet = b''
        base_packet += self.sender.bytes
        base_packet += self.receiver.bytes
        base_packet += self.command.value.to_bytes(1, 'big') # Server commands
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

class Server():

    def __init__(self, ip="0.0.0.0", port=9999, owner=None):
        self.bind_ip = ip
        self.bind_port = port
        self.uuid = uuid.uuid4()
        self.__owner = owner
        self.__admissionkeys = {}
        self.__clients = {}
        self.__uuiddns = {}
        self.__mailboxes = {}
        self.__commands = {
            Command.TRANSMIT: self._transmit,
            Command.ADDCLIENT: self._add_client,
            Command.REGISTER: self._register,
            Command.SHAREKEY: self._transmit,
            Command.ACK: self._swallow,
            Command.RECEIVE: self._receive,
        }
        self.serverrsa = RSAHelper()
        self.serverrsa.generateKeys()

    def _swallow(self, packet: Packet):
        '''
        Ignore the request
        '''
        pass

    def __createadmissionkey(self):
        '''
        An admission key consists of the key itself (an integer between 0 and one million)
        and the expiration time (5 minutes after creation)
        '''
        key = random.randint(0, 999999)
        ts = time.time() + 300
        key = str(key)
        while len(key) < 6:
            key = '0' + key
        self.__admissionkeys[key] = ts
        return key

    def _add_client(self, packet: Packet):
        '''
        Can only be called by the owner.
        Server generates a key and returns it for the new client to use
        '''
        p = None
        if packet.sender == self.__owner:
            p = self.__generate_ack()
            p.payload = key.to_bytes()
        return p

    def __verify_packet(self, packet: Packet):
        '''
        If the decrypted packet has a valid sender and receiver UUID, then it's valid
        '''
        check = packet.receiver in self.__clients or packet.receiver == self.uuid
        check |= (packet.receiver == uuid.UUID(int=0) and packet.command == Command.REGISTER)
        check &= packet.sender in self.__clients
        return check

    def _transmit(self, packet: Packet):
        p = self__generate_ack(packet)
        p.command = Command.FAIL
        if self.__verify_packet(packet) and packet.receiver != self.uuid:
            self.__mailboxes[packet.receiver].append(packet)
            p.command = Command.ACK
        return p

    def __generate_ack(self, packet: Packet):
        p = Packet()
        p.receiver = packet.sender
        p.sender = self.uuid
        p.command = Command.ACK
        p.rsa = self.serverrsa
        p.payload = (1).to_bytes(1, 'big')
        return p

    def _register(self, packet: Packet):
        '''
        Checks if key provided is register already.
        If so, and if the key hasn't expired, adds the client as a new client and removes the key
        '''
        key = packet.payload[0:6].decode()
        print(key)
        p = self.__generate_ack(packet)
        p.command = Command.FAIL
        if key in self.__admissionkeys.keys() and self.__admissionkeys[key] > time.time():
            self.__admissionkeys.pop(key)
            pem = packet.payload[6:]
            print(pem)
            self.__clients[packet.sender] = self.serverrsa.pem2key(pem)
            self.__mailboxes[packet.sender] = []
            p.command = Command.ACK
        return p

    def _send(self, sock, packet: Packet):
        for p in packet.build(server=True):
            sock.send(p)

    def _receive(self, packet):
        pass

    def run(self):
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        server.bind((self.bind_ip, self.bind_port))

        key = self.__createadmissionkey()
        print(f"[ * ] Listening on {self.bind_ip}:{self.bind_port}")
        print(f"[ * ] Owner registration key: {key}")

        # max server backlog == 5
        server.listen(5)
        def handle_client(client_socket):
            bytes = client_socket.recv(512)

            pack = Packet()
            pack.rsa = self.serverrsa
            sig = bytes[256]
            try:
                bytes = pack.decrypt(bytes, decryptpayload=False)
                self.serverrsa.verify(sig, bytes)
                pack.from_bytes(bytes)

            except ValueError:
                print("REgister")
                pack.from_bytes(bytes)
                if pack.command != Command.REGISTER:
                    client_socket.close()
                    return
                more_bytes = client_socket.recv(228)
                pack.payload += more_bytes

            if self.__verify_packet(pack) or pack.command == Command.REGISTER:
                resp = self.__commands[pack.command](pack)
                self._send(client_socket, resp)

            client_socket.close()

        while True:
            client, addr = server.accept()
            print(f"[ * ] Accepted connection from {addr[0]}:{addr[1]}")

            client_handler = threading.Thread(target=handle_client, args=(client,))
            client_handler.start()

serv = Server()
serv.run()