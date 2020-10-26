import uuid
import socket
import random
import logging
import datetime
import threading

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

import logging
from cryptography.hazmat.primitives.asymmetric import rsa




class Server():

    def __init__(self, ip="0.0.0.0", port=9999, owner=None):
        self.bind_ip = ip
        self.bind_port = port
        self.uuid = uuid.UUID()
        self.__owner = owner
        self.__admissionkeys = {}
        self.__clients = []
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
        ts = datetime.datetime.timestamp() + 300
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
        p = None
        if self.__verify_packet(packet) and packet.receiver != self.uuid:
            self.__mailboxes[packet.receiver].append(packet)
            p = self.__generate_ack(packet)
        return p

    def __generate_ack(self, packet: Packet):
        p = Packet()
        p.receiver = packet.sender
        p.sender = self.uuid
        p.command = Command.ACK
        p.payload = (1).to_bytes(1)
        return p

    def _register(self, packet: Packet):
        '''
        Checks if key provided is register already.
        If so, and if the key hasn't expired, adds the client as a new client and removes the key
        '''
        key = packet.payload[0:7]
        p = None
        if key in self.__admissionkeys.keys() and self.__admissionkeys[key] > datetime.datetime.timestamp():
            self.__admissionkeys.pop(key)
            common_name = packet.payload[7:]
            self.__clients.append(packet.sender)
            self.__uuiddns[common_name] = packet.sender
            self.__mailboxes[packet.sender] = []
            p = self.__generate_ack(packet)
        return p

    def _send(self, sock, packet: Packet):
        for p in packet.build():
            sock.send(p)

    def _transmit(self, packet):
        pass
    
    def decryptHeader(encrypted_header):
        #should decrypt the header with RSA 
        #has a complemtary encryptHeader on the server
        #https://cryptography.io/en/latest/hazmat/primitives/asymmetric/rsa/
        return decryptedHeader


    def run(self):
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        server.bind((self.bind_ip, self.bind_port))

        # max server backlog == 5
        server.listen(5)

        logging.info(f"[ * ] Listening on {self.bind_ip}:{self.bind_port}")

        def handle_client(client_socket):

            bit_size = client_socket.recv(16)
            size = int(bit_size, 2)

            if size > 12:
                remaining_size = size - 12
                remaining_bits = client_socket.recv(remaining_size)

            pack = Packet()
            pack.from_bytes(remaining_bits)
            pack.decrypt()

            resp = self.__commands[pack.command](pack)
            self._send(client_socket, resp)

            client_socket.close()

        while True:
            client, addr = server.accept()
            logging.info(f"[ * ] Accepted connection from {addr[0]}:{addr[1]}")

            client_handler = threading.Thread(target=handle_client, args=(client,))
            client_handler.start()
