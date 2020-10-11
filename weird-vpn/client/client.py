import socket


class Client():

    def __init__(self, server_host="127.0.0.1", server_port=9999)
        self.server_host = "127.0.0.1"
        self.port = 9999
        self.__client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    def run(self):
        pass

client.connect((target_host, target_port))

client.send("message")