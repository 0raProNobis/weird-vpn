import uuid

class Packet():

    sender = uuid.UUID() # set to random UUID, should be overwritten
    receiver = uuid.UUID() # set to random UUID, should be overwritten
    data = b''
    max_size = 65536 # maximum number for two byte integer, which we use for the length field

    def __init__(self):
        pass

    def encrypt_data(self):
        # TODO: encrypt self.data here
        pass

    def build(self):
        # first twelve bits is the packet size
        meta_length = 12

        # Sender and receiver should be 128 bit UUIDs
        if self.sender:
            meta_length += 128
        if self.receiver:
            meta_length += 128

        remaining_data = self.data
        while len(remaining_data) != 0:
            if len(remaining_data) > (self.max_size - meta_length):
                packet_data = remaining_data[:self.max_size - meta_length]
                remaining_data = remaining_data[self.max_size - meta_length:]
            else:
                packet_data = remaining_data
                remaining_data = b''

            # Create header information for server
            packet = b''
            packet += (meta_length+len(packet_data)).to_bytes(2)
            packet += self.sender.bytes()
            packet += self.receiver.bytes()
            packet += (0).to_bytes(1) # Server commands

            # Add payload data
            packet += packet_data

            # TODO: whole packet encryption here

            yield packet
