import sys
import time
import uuid
import socket
import signal
import random
import threading

from cryptohelper import RSAHelper
from packet import Command, Packet


class Server():

    def __init__(self, ip="0.0.0.0", port=9999, owner=None):
        self.bind_ip = ip
        self.bind_port = port
        self.uuid = uuid.uuid4()
        self.__owneruuid = owner
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

    def _swallow(self, packet: Packet, sock=None):
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

    def _add_client(self, packet: Packet, sock=None):
        '''
        Can only be called by the owner.
        Server generates a key and returns it for the new client to use
        '''
        p = self.__generate_ack(packet)
        p.command = Command.FAIL
        if packet.sender == self.__owneruuid:
            p.command = Command.ACK
            key = self.__createadmissionkey()
            p.payload = key.encode()
        return p

    def __verify_packet(self, packet: Packet):
        '''
        If the decrypted packet has a valid sender and receiver UUID, then it's valid
        '''
        check = packet.receiver in self.__clients or packet.receiver == self.uuid
        check |= (packet.receiver == uuid.UUID(int=0) and packet.command == Command.REGISTER)
        check &= packet.sender in self.__clients
        return check

    def _transmit(self, packet: Packet, sock=None):
        p = self.__generate_ack(packet)
        p.command = Command.FAIL
        if packet.receiver != self.uuid:
            self.__mailboxes[packet.receiver].append(packet)
            p.command = Command.ACK
        return p

    def __generate_ack(self, packet: Packet):
        p = Packet()
        p.receiver = packet.sender
        p.sender = self.uuid
        p.command = Command.ACK
        p.rsa = self.serverrsa
        if packet.sender in self.__clients.keys():
            p.pubkey = self.__clients[packet.sender]
        p.payload = (1).to_bytes(1, 'big')
        return p

    def _register(self, packet: Packet, sock=None):
        '''
        Checks if key provided is register already.
        If so, and if the key hasn't expired, adds the client as a new client and removes the key
        '''
        key = packet.payload[0:6].decode()
        p = self.__generate_ack(packet)
        p.command = Command.FAIL
        if key in self.__admissionkeys.keys() and self.__admissionkeys[key] > time.time():
            notifyowner = True
            self.__admissionkeys.pop(key)
            pem = packet.payload[6:]
            self.__clients[packet.sender] = self.serverrsa.pem2key(pem)
            self.__mailboxes[packet.sender] = []
            p.command = Command.SHAREPUB
            if self.__owneruuid is None:
                self.__owneruuid = packet.sender
                notifyowner = False
            p.payload = self.__owneruuid.bytes + self.serverrsa.pubkey2pem()

            if notifyowner:
                p2 = self.__generate_ack(packet)
                p2.command = Command.SHAREKEY
                p2.receiver = self.__owneruuid
                p2.payload = packet.sender.bytes
                self.__mailboxes[self.__owneruuid].append(p2)

        return p

    def _send(self, sock, packet: Packet):
        for p in packet.build(server=True):
            sock.send(p)

    def _receive(self, packet, sock=None):
        queue = self.__mailboxes[packet.sender]
        p = self.__generate_ack(packet)
        p.command = Command.QUERYMAILBOX
        p.payload = len(queue).to_bytes(8, 'big')
        self._send(sock, p)
        count = len(queue)
        for i in range(count):
            pack = queue.pop(0)
            if pack is None:
                return
            pack.pubkey = self.__clients[packet.sender]
            self._send(sock, pack)

    def sig_kill(self, sig, frame):
        self.server.close()
        sys.exit(0)

    def run(self):
        signal.signal(signal.SIGINT, self.sig_kill)
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        self.server.bind((self.bind_ip, self.bind_port))

        key = self.__createadmissionkey()
        print(f"[ * ] Listening on {self.bind_ip}:{self.bind_port}")
        print(f"[ * ] Owner registration key: {key}")

        # max server backlog == 5
        self.server.listen(5)
        def handle_client(client_socket):
            bytes = client_socket.recv(512)
            pack = Packet()
            pack.rsa = self.serverrsa
            sig = bytes[:256]
            try:
                bytes = pack.decrypt(bytes[256:])
                pack.from_bytes(bytes)

                # Not working for some reason
                self.serverrsa.verify(bytes, sig, self.__clients[pack.sender])


            except ValueError:
                pack.from_bytes(bytes)
                if pack.command != Command.REGISTER:
                    client_socket.close()
                    return

            if self.__verify_packet(pack) or pack.command == Command.REGISTER:
                resp = self.__commands[pack.command](pack, sock=client_socket)
                if resp is not None:
                    self._send(client_socket, resp)

            client_socket.close()

        while True:
            client, addr = self.server.accept()
            print(f"[ * ] Accepted connection from {addr[0]}:{addr[1]}")

            client_handler = threading.Thread(target=handle_client, args=(client,))
            client_handler.start()
