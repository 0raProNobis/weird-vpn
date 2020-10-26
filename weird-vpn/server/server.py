import socket
import threading
import uuid
import logging
from cryptography.hazmat.primitives.asymmetric import rsa
from ..common.packet import Packet, Command


class Server():

    def __init__(self, ip="0.0.0.0", port=9999, owner=None):
        self.bind_ip = ip
        self.bind_port = port
        self.owner = owner
        self.__clients = []
        self.__commands = {Command.TRANSMIT: self._transmit, Command.ADDCLIENT: self._add_client}

    def _add_client(self, packet):
        pass

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

            self.__commands[pack.command](pack)

            client_socket.close()

        while True:
            client, addr = server.accept()
            logging.info(f"[ * ] Accepted connection from {addr[0]}:{addr[1]}")

            client_handler = threading.Thread(target=handle_client, args=(client,))
            client_handler.start()
