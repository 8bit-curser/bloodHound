from time import sleep, time
from pprint import pprint as pp
from select import select
from socket import (AF_INET, IPPROTO_ICMP, IP_TTL, SOCK_RAW, SOL_IP,
                    gethostbyname, gethostname, htons, socket)
from struct import calcsize, pack, unpack
from argparse import ArgumentParser
from datetime import datetime as dt
from threading import current_thread
from subprocess import call

from _thread import start_new_thread
from constants_ns import (ECHO_REPLY, ECHO_REQUEST, ICMP_DEFAULT_CODE,
                          ICMP_HEADER_FORMAT, ICMP_TIME_FORMAT,
                          IP_HEADER_FORMAT, MAX_DOTS, TIME_EXCEEDED)

START = True


def ones_comp_sum16(num1: int, num2: int) -> int:
    """Calculates the 1's complement sum for 16-bit numbers.
    Args:
        num1: 16-bit number.
        num2: 16-bit number.
    Returns:
        The calculated result.
    """

    carry = 1 << 16
    result = num1 + num2
    result = result if result < carry else result + 1 - carry
    return result


def checksum(source: bytes) -> int:
    """Calculates the checksum of the input bytes.
    RFC1071: https://tools.ietf.org/html/rfc1071
    RFC792: https://tools.ietf.org/html/rfc792
    Args:
        source: The input to be calculated.
    Returns:
        Calculated checksum.
    """
    # if the total length is odd, padding with one octet of zeros for computing
    # the checksum
    if len(source) % 2:
        source += b'\x00'
    sum_ = 0
    for i in range(0, len(source), 2):
        sum_ = ones_comp_sum16(sum_, (source[i + 1] << 8) + source[i])
    ret = ~sum_ & 0xffff
    return ret


def send_one_ping(
        sock, dest_addr: str, icmp_id: int,
        seq: int = 0, size: int = 56) -> None:
    """Sends a ICMP package to a destination address.
    Args:
        sock -- (obj) socket instance.
        dest_addr -- (str) ip or dns of target.
        icmp_id -- (int) ICMP packet id. Sent packet id should be identical to.
        seq -- (int) ICMP packet sequence. Sent packet sequence should be
        identical.
        size -- (int) The ICMP packet payload size in bytes.
    """
    pseudo_checksum = 0
    icmp_header = pack(
        ICMP_HEADER_FORMAT, ECHO_REQUEST, ICMP_DEFAULT_CODE,
        pseudo_checksum, icmp_id, seq
    )
    padding = (
        size - calcsize(ICMP_TIME_FORMAT) - calcsize(ICMP_HEADER_FORMAT)) * "Q"
    icmp_payload = pack(ICMP_TIME_FORMAT, time()) + padding.encode()
    real_checksum = checksum(icmp_header + icmp_payload)
    icmp_header = pack(
        ICMP_HEADER_FORMAT, ECHO_REQUEST, ICMP_DEFAULT_CODE,
        htons(real_checksum), icmp_id, seq
    )  # Put real checksum into ICMP header.
    packet = icmp_header + icmp_payload
    # behavior will be used.
    sock.sendto(packet, (dest_addr, 0))


def receive_one_ping(
        sock: socket, icmp_id: int, seq: int, timeout: int) -> True or False:
    """Receives the ping from the socket.
    IP Header (bits): version (8), type of service (8), length (16), id (16),
    flags (16), time to live (8), protocol (8), checksum (16), source ip (32),
    destination ip (32).
    ICMP Packet (bytes): IP Header (20), ICMP Header (8), ICMP Payload (*).
    Ping Wikipedia: https://en.wikipedia.org/wiki/Ping_(networking_utility)
    ToS (Type of Service) in IP header for ICMP is 0. Protocol in IP
    header for ICMP is 1.
    Args:
        sock: The same socket used for send the ping.
        icmp_id: ICMP packet id. Sent packet id should be identical with
        received packet id.
        seq: ICMP packet sequence. Sent packet sequence should be identical
        with received packet sequence.
        timeout: Timeout in seconds.
    Returns:
        True or False, True when the server responds, False if it doesn't.
    """
    ret = True
    ip_header_slice = slice(0, calcsize(IP_HEADER_FORMAT))  # [0:20]
    icmp_header_slice = slice(
        ip_header_slice.stop,
        ip_header_slice.stop + calcsize(ICMP_HEADER_FORMAT)
    )  # [20:28]
    icmp_header_keys = ('type', 'code', 'checksum', 'id', 'seq')
    while True:
        selected = select([sock], [], [], timeout)
        if selected[0] == []:
            ret = False
            break
        recv_data, addr = sock.recvfrom(1024)
        icmp_header_raw = recv_data[icmp_header_slice]
        icmp_header = dict(
            zip(icmp_header_keys, unpack(ICMP_HEADER_FORMAT, icmp_header_raw)))
        if icmp_header['type'] == TIME_EXCEEDED:
            ret = False
            break
        if icmp_header['id'] == icmp_id and icmp_header['seq'] == seq:
            if icmp_header['type'] == ECHO_REPLY:
                break
    return ret


def waiter():
    """Waiter prints while scanning."""
    call('clear', shell=True)
    while START:
        print('Scanning: ', end='', flush=True)
        for _ in range(MAX_DOTS):
            print('.', end='', flush=True)
            sleep(0.2)
        call('clear', shell=True)


def pinger(range_):
    start_new_thread(waiter, ())
    for end in range(range_[0], range_[1]):
        host = '{}.{}'.format(my_network_template, str(end))
        # Generate a IPV4, RAW socket that can work with ICMP
        with socket(AF_INET, SOCK_RAW, IPPROTO_ICMP) as sock:
            #  print('host: {}'.format(host))
            sock.setsockopt(SOL_IP, IP_TTL, 64)
            icmp_id = current_thread().ident % 0xFFFF
            send_one_ping(
                sock=sock, dest_addr=host, icmp_id=icmp_id, seq=0, size=56)
            delay = receive_one_ping(
                sock=sock, icmp_id=icmp_id, seq=0, timeout=4)
            if delay:
                succ.append(host)
            sock.close()
    START = False


if __name__ == '__main__':
    succ = []
    my_ip = gethostbyname(gethostname())
    my_network_template = '.'.join(my_ip.split('.')[:3])
    # Arguments catching
    parser = ArgumentParser()
    parser.add_argument(
        '--f', '-full', help='Full scan of 255 possibilties.',
        action='store_true')
    parser.add_argument(
        '--r', '-range', help='Range of IPS accesible, e.g: 100-125',
        default='0-20'
        )
    # Parse arguments
    args = parser.parse_args()
    range_ = '0-255' if args.f else args.r
    ranges = list(map(int, range_.split('-')))
    # Run and calculate time
    before = dt.now()
    pinger(ranges)
    after = dt.now()
    delta = after - before
    #  call('clear', shell=True)
    print('Scan took: {} seconds'.format(delta.seconds))
    print('Your IP: {}'.format(my_ip))
    succ.remove(my_ip)
    print('Nodes found:')
    pp(succ)
