import sys
import argparse

from client import Client
from server import Server


parser = argparse.ArgumentParser(prog='', description="")
command_group = parser.add_mutually_exclusive_group(required=True)
parser.add_argument('address', type=str)
parser.add_argument('-p', '--port', type=int)
command_group.add_argument('-t', '--transmit', type=str)
command_group.add_argument('-r', '--receive', action='store_true')
command_group.add_argument('--addclient', action='store_true')
command_group.add_argument('--register', action='store_true')
command_group.add_argument('--server', action='store_true')
parser.add_argument('-i', '--id', type=int, required=('-t' in sys.argv or '--transmit' in sys.argv))

args = parser.parse_args()

print(args.server)
print(args.register)
if args.server and args.port:
    serv = Server(ip=args.address, port=args.port)
    serv.run()
elif args.server:
    serv = Server(ip=args.address)
    serv.run()
else:
    if args.port:
        client = Client(server_host=args.address, server_port=args.port)
    else:
        client = Client(server_host=args.address)

    if args.transmit:
        client.transmit(args.id, args.transmit)
    elif args.receive:
        client.receive()
    elif args.addclient:
        client.addclient()
    else:
        client.register()
