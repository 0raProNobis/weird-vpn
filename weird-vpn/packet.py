import uuid
import enum

from cryptohelper import AESHelper, RSAHelper


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
        if self.command == Command.REGISTER:
            packet = base_packet + remaining_data
            remaining_data = b''
            print(len(packet))
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
