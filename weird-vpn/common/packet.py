import uuid
import enum
from rsaDecrypt import *
from rsaEncrypt import *

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import PublicFormat
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.hazmat.primitives import serialization

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

    def encrypt_key(self, data, key):
        pass

    def decrypt_key(self, key):
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
    
    def rsa_encrypt(packetToEncrypt,nameFileToSaveTo,rsaPublicFile,rsaPrivateFile,nameOfSigFileToSave):
        #encrypts data using rsa, variable names temporary to add clarity, can change to whatever
        #see rsaEncrypt.py for more details
        encrypt(packetToEncrypt,nameFileToSaveTo,rsaPublicFile,rsaPrivateFile,nameOfSigFileToSave)
        
    def rsa_decrypt(encryptFileName,SigName,rsaPublicFile,rsaPrivateFile,saveFileName):
        #decrypts rsa, variable names temporary to add clarity, can change to whatever
        #see rsaDecrypt.py for more details
        decrypt(encryptFileName,SigName,rsaPublicFile,rsaPrivateFile,saveFileName)
        
    def build(self, public_key, symmetric_key, sharing_key=False):
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
