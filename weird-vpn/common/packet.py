import uuid
import enum


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

    def from_bytes(self, bytes):
        pass

    def encrypt_payload(self):
        # TODO: encrypt self.payload here
        pass

    def decrypt_payload(self):
        pass

    def decrypt(self):
        pass

    def encrypt(self):
        pass

    def build(self):
        # first sixteen bits is the packet size
        meta_length = 16

        # Sender and receiver should be 128 bit UUIDs
        if self.sender:
            meta_length += 128
        if self.receiver:
            meta_length += 128

        remaining_data = self.payload
        while len(remaining_data) != 0:
            if len(remaining_data) > (self.max_size - meta_length):
                packet_data = remaining_data[:self.max_size - meta_length]
                remaining_data = remaining_data[self.max_size - meta_length:]
            else:
                packet_data = remaining_data
                remaining_data = b''

            # Create header information for server
            packet = b''
            packet = (meta_length+len(packet_data)).to_bytes(2) + packet
            packet += self.sender.bytes()
            packet += self.receiver.bytes()
            packet += (0).to_bytes(1) # Server commands

            # Add payload data
            packet += packet_data

            # TODO: whole packet encryption here
            yield packet
