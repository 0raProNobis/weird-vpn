import uuid
import enum
from rsaDecrypt import *
from rsaEncrypt import *


class Command(enum.Enum):
    TRANSMIT = 0
    ACK = 1
    ADDCLIENT = 2


class Packet():

    sender = uuid.UUID() # set to random UUID, should be overwritten
    receiver = uuid.UUID() # set to random UUID, should be overwritten
    payload = b''
    max_size = 65536 # maximum number for two byte integer, which we use for the length field
    command = Command.TRANSMIT

    def __init__(self):
        pass

    def from_bytes(self, data):
        pass

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
    
    def rsa_encrypt(packetToEncrypt,nameFileToSaveTo,rsaPublicFile,rsaPrivateFile,nameOfSigFileToSave):
        #encrypts data using rsa, variable names temporary to add clarity, can change to whatever
        #see rsaEncrypt.py for more details
        encrypt(packetToEncrypt,nameFileToSaveTo,rsaPublicFile,rsaPrivateFile,nameOfSigFileToSave)
        
    def rsa_decrypt(encryptFileName,SigName,rsaPublicFile,rsaPrivateFile,saveFileName):
        #decrypts rsa, variable names temporary to add clarity, can change to whatever
        #see rsaDecrypt.py for more details
        decrypt(encryptFileName,SigName,rsaPublicFile,rsaPrivateFile,saveFileName)
        
    def build(self, public_key, symmetric_key, sharing_key=False):
        # first sixteen bits is the packet size
        meta_length = 16

        # Sender and receiver should be 128 bit UUIDs
        if self.sender:
            meta_length += 128
        if self.receiver:
            meta_length += 128

        remaining_data = self.payload
        remaining_size = self.max_size - meta_length
        while len(remaining_data) != 0:
            if len(remaining_data) > remaining_size:
                packet_data = remaining_data[:remaining_size]
                remaining_data = remaining_data[remaining_size:]
            else:
                packet_data = remaining_data + (b'0' * remaining_size)
                remaining_data = b''

            # Create header information for server
            packet = b''
            packet = (meta_length+len(packet_data)).to_bytes(2) + packet
            packet += self.sender.bytes()
            packet += self.receiver.bytes()
            packet += (0).to_bytes(1) # Server commands

            # Add payload data
            if sharing_key:
                packet_data = self.encrypt_key()
            else:
                packet_data = self.encrypt_payload()
            packet += packet_data

            # TODO: whole packet encryption here
            yield packet
