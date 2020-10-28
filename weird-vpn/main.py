import sys
import argparse

from client import Client
from server import Server


parser = argparse.ArgumentParser(prog='', description="")
command_group = parser.add_mutually_exclusive_group(required=True)
parser.add_argument('address', type=str)
parser.add_argument('-p', '--port', type=int)
parser.add_argument('-m', '--memoryfilepath', type=str)
command_group.add_argument('-t', '--transmit', type=str)
command_group.add_argument('-r', '--receive', action='store_true')
command_group.add_argument('--addclient', action='store_true')
command_group.add_argument('--register', action='store_true')
command_group.add_argument('--server', action='store_true')
command_group.add_argument('-s', '--sharekey', action='store_true')
parser.add_argument('-i', '--id', type=str, required=('-t' in sys.argv or '--transmit' in sys.argv))

args = parser.parse_args()

if args.server and args.port:
    serv = Server(ip=args.address, port=args.port)
    serv.run()
elif args.server:
    serv = Server(ip=args.address)
    serv.run()
else:

    if args.port and args.memoryfilepath:
        client = Client(server_host=args.address, server_port=args.port, filepath=args.memoryfilepath)
    elif args.port:
        client = Client(server_host=args.address, server_port=args.port)
    elif args.memoryfilepath:
        client = Client(server_host=args.address, filepath=args.memoryfilepath)
    else:
        client = Client(server_host=args.address)


    if args.transmit:
        client.transmit(args.id, args.transmit)
    elif args.receive:
        client.receive()
    elif args.addclient:
        client.addclient()
    elif args.sharekey:
        client.sharekey()
    else:
        client.register()
    print(f'Owner: {client.owneruuid}')
    print(f'You: {client.uuid}')