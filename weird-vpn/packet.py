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
    max_size = 190
    command = Command.TRANSMIT
    aeskey: bytes = b''
    aeshelp: AESHelper = AESHelper()
    rsa: RSAHelper = None
    pubkey = None


    def __init__(self):
        pass

    def trim_payload(self):
        pass

    def from_bytes(self, data):
        self.sender = uuid.UUID(bytes=data[:16])
        self.receiver = uuid.UUID(bytes=data[16:32])
        self.command = Command(int.from_bytes(data[32:33], 'big'))
        self.payload = data[33:]
        if self.command in [Command.ADDCLIENT, Command.REGISTER,
                            Command.QUERYCLIENTS, Command.QUERYMAILBOX]:
            self.trim_payload()

    def encrypt_payload(self, data):
        self.aeshelp.setkey(self.aes)
        return self.aeshelp.encrypt(data)

    def decrypt_payload(self):
        self.aeshelp.setkey(self.aes)
        self.payload = self.aeshelp.decrypt(self.payload)

    def decrypt(self, data):
        return self.rsa.decrypt(data)

    def encrypt(self, data):
        return self.rsa.encrypt(data, self.pubkey)
        
    def build(self, server=False, encrypt=True):
        # Sender and receiver should be 128 bit UUIDs
        meta_length = 33

        remaining_data = self.payload
        remaining_size = self.max_size - meta_length
        base_packet = b''
        base_packet += self.sender.bytes
        base_packet += self.receiver.bytes
        base_packet += self.command.value.to_bytes(1, 'big') # Server commands
        sentone = False
        if self.command == Command.REGISTER or self.command == Command.SHAREPUB:
            packet = base_packet + remaining_data
            remaining_data = b''
            yield packet
            sentone = True
        while len(remaining_data) != 0 or not sentone:
            if len(remaining_data) > remaining_size and sentone:
                packet_data = remaining_data[:remaining_size]
                remaining_data = remaining_data[remaining_size:]
            elif encrypt:
                packet_data = remaining_data
                remaining_data = b''
            else:
                packet_data = remaining_data + (b'0' * (remaining_size - len(remaining_data)))
                remaining_data = b''

            # Create header information for server
            packet = base_packet

            # Add payload data
            if encrypt and not server:
                packet += self.encrypt_payload(packet_data)
            else:
                packet += packet_data

            if encrypt:
                packet = self.encrypt(packet)

            yield packet
            sentone = True
