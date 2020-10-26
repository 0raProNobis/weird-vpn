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
