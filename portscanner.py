from pprint import pprint as pp
from socket import (AF_INET, AF_INET6, SOCK_DGRAM, SOCK_STREAM, error,
                    gaierror, socket)
from argparse import ArgumentParser
from subprocess import call

MAX_PORT = 65535
COMMON_PORTS = []
LOCALHOST = '127.0.0.1'

PORT_TYPE = {
    'TCP': SOCK_STREAM,
    'UDP': SOCK_DGRAM,
}

HOST_TYPE = {
    'IPV4': AF_INET,
    'IPV6': AF_INET6,
}

parser = ArgumentParser()

parser.add_argument(
    '--h', '-host', help='Host to be looked on, e.g. 127.0.0.1',
    default=LOCALHOST
    )

parser.add_argument(
    '--p', '-port', help='Specify the port number to look on, e.g 80',
    default=0
    )

parser.add_argument(
    '--pt', '-porttype', help='Specify the port type e.g ALL, TCP, UDP',
    default='TCP'
    )

parser.add_argument(
    '--ht', '-hosttype', help='Specify the host type e.g ALL, IPV4, IPV6',
    default='IPV4'
    )

parser.add_argument(
    '--f', '-full', help='Initialize a full scan', action='store_true'
    )

parser.add_argument(
    '--c', '-common', help='Initialize a common scan', action='store_true'
    )
args = parser.parse_args()

port_type = PORT_TYPE.get(args.pt)
host_type = HOST_TYPE.get(args.ht)
opened = []
close = []

call('clear', shell=True)

if args.f:
    for port in range(MAX_PORT):
        pass
elif args.c:
    for port in COMMON_PORTS:
        pass
else:
    try:
        s = socket(host_type, port_type)
        s.connect((args.h, int(args.p)))
        opened.append((args.h, args.p))
    except gaierror:
        print("Can't resolve hostname")
    except error:
        close.append((args.h, args.p))
    except ConnectionRefusedError:
        close.append((args.h, args.p))

print('Open:\n')
pp(opened)
print('Closed:\n')
pp(close)
