import socket
import time
import hashlib
import socks
import logging
import random

from io import BytesIO
from random import randint
from base64 import b32decode, b32encode
from queue import Queue
from threading import Thread, Lock

from db import observe_node, observe_error, create_tables


logging.basicConfig(level="INFO", filename='crawler.log', 
        format='%(threadName)-6s %(asctime)s %(message)s')
logger = logging.getLogger(__name__)

NETWORK_MAGIC = b'\xf9\xbe\xb4\xd9'

# docs say it should be this but p2p network seems end b"\x00" x2
# IPV4_PREFIX = b"\x00" * 10 + b"\xff" * 2
IPV4_PREFIX = b"\x00" * 10 + b"\x00" * 2
ONION_PREFIX = b"\xFD\x87\xD8\x7E\xEB\x43"  # ipv6 prefix for .onion address
DNS_SEEDS = [
    'dnsseed.bitcoin.dashjr.org',
    'dnsseed.bluematt.me',
    'seed.bitcoin.sipa.be',
    'seed.bitcoinstats.com',
    'seed.bitcoin.sprovoost.nl',
    'seed.bitnodes.io',
]


def little_endian_to_int(b):
    return int.from_bytes(b, 'little')


def int_to_little_endian(n, length):
    return n.to_bytes(length, 'little')


def big_endian_to_int(b):
    return int.from_bytes(b, 'big')


def int_to_big_endian(n, length):
    return n.to_bytes(length, 'big')


def double_sha256(s):
    return hashlib.sha256(hashlib.sha256(s).digest()).digest()


def bytes_to_ip(b):
    if b[:6] == ONION_PREFIX:
        return b32encode(b[6:]).lower().decode("ascii") + ".onion"
    elif b[0:12] == IPV4_PREFIX:  # IPv4
        return socket.inet_ntop(socket.AF_INET, b[12:16])
    else:  # IPv6
        return socket.inet_ntop(socket.AF_INET6, b)


def ip_to_bytes(ip):
    if ip.endswith(".onion"):
        return ONION_PREFIX + b32decode(ip[:-6], True)
    elif ":" in ip:
        return socket.inet_pton(socket.AF_INET6, ip)
    else:
        return IPV4_PREFIX + socket.inet_pton(socket.AF_INET, ip)


def read_varint(s):
    '''read_varint reads a variable integer from a stream'''
    i = s.read(1)[0]
    if i == 0xfd:
        # 0xfd means the next two bytes are the number
        return little_endian_to_int(s.read(2))
    elif i == 0xfe:
        # 0xfe means the next four bytes are the number
        return little_endian_to_int(s.read(4))
    elif i == 0xff:
        # 0xff means the next eight bytes are the number
        return little_endian_to_int(s.read(8))
    else:
        # anything else is just the integer
        return i


def encode_varint(i):
    '''encodes an integer as a varint'''
    if i < 0xfd:
        return bytes([i])
    elif i < 0x10000:
        return b'\xfd' + int_to_little_endian(i, 2)
    elif i < 0x100000000:
        return b'\xfe' + int_to_little_endian(i, 4)
    elif i < 0x10000000000000000:
        return b'\xff' + int_to_little_endian(i, 8)
    else:
        raise RuntimeError('integer too large: {}'.format(i))


def read_version_payload(stream):
    r = {}
    r["version"] = little_endian_to_int(stream.read(4))
    r["services"] = little_endian_to_int(stream.read(8))
    r["timestamp"] = little_endian_to_int(stream.read(8))
    r["receiver_services"] = little_endian_to_int(stream.read(8))
    r["receiver_ip"] = bytes_to_ip(stream.read(16))
    r["receiver_port"] = big_endian_to_int(stream.read(2))
    r["sender_services"] = little_endian_to_int(stream.read(8))
    r["sender_ip"] = bytes_to_ip(stream.read(16))
    r["sender_port"] = big_endian_to_int(stream.read(2))
    r["nonce"] = little_endian_to_int(stream.read(8))
    r["user_agent"] = stream.read(read_varint(stream))
    r["latest_block"] = little_endian_to_int(stream.read(4))
    r["relay"] = little_endian_to_int(stream.read(1))
    return r


def serialize_version_payload(
        version=70015, services=1, timestamp=None,
        receiver_services=1,
        receiver_ip='0.0.0.0', receiver_port=8333,
        sender_services=1,
        sender_ip='0.0.0.0', sender_port=8333,
        nonce=None, user_agent=b'/buidl-bootcamp/',
        latest_block=0, relay=True):
    if timestamp is None:
        timestamp = int(time.time())
    if nonce is None:
        nonce = randint(0, 2**64)
    result = int_to_little_endian(version, 4)
    result += int_to_little_endian(services, 8)
    result += int_to_little_endian(timestamp, 8)
    result += int_to_little_endian(receiver_services, 8)
    result += ip_to_bytes(receiver_ip)
    result += int_to_big_endian(receiver_port, 2)
    result += int_to_little_endian(sender_services, 8)
    result += ip_to_bytes(sender_ip)
    result += int_to_little_endian(sender_port, 2)
    result += int_to_little_endian(nonce, 8)
    result += encode_varint(len(user_agent))
    result += user_agent
    result += int_to_little_endian(latest_block, 4)
    result += int_to_little_endian(int(relay), 1)
    return result


def read_address(stream):
    r = {}
    r["time"] = little_endian_to_int(stream.read(4))
    r["services"] = stream.read(8)
    r["ip"] = bytes_to_ip(stream.read(16))
    r["port"] = big_endian_to_int(stream.read(2))
    return r


def read_addr_payload(stream):
    r = {}
    count = read_varint(stream)
    r["addresses"] = [read_address(stream) for _ in range(count)]
    return r


def read_msg(stream):
    magic = stream.read(4)
    if magic != NETWORK_MAGIC:
        raise Exception(f'Magic is wrong: {magic}')
    command = stream.read(12)
    command = command.strip(b'\x00')
    payload_length = int.from_bytes(stream.read(4), 'little')
    checksum = stream.read(4)
    payload = stream.read(payload_length)
    calculated_checksum = double_sha256(payload)[:4]
    if calculated_checksum != checksum:
        raise Exception('Checksum does not match')
    return {
        "command": command,
        "payload": payload,
    }


def serialize_msg(command, payload=b''):
    result = NETWORK_MAGIC
    result += command + b'\x00' * (12 - len(command))
    result += int_to_little_endian(len(payload), 4)
    result += double_sha256(payload)[:4]
    result += payload
    return result


def connect(address):
    if 'onion' in address[0]:
        sock = socks.create_connection(
            address,
            timeout=20,
            proxy_type=socks.PROXY_TYPE_SOCKS5,
            proxy_addr="127.0.0.1",
            proxy_port=9050
        )
    else:
        sock = socket.create_connection(address, timeout=20)
    return sock


def handshake(address):
    sock = socket.create_connection(address, 20)
    stream = sock.makefile("rb")

    # Step 1: our version message
    payload = serialize_version_payload()
    msg = serialize_msg(command=b"version", payload=payload)
    sock.sendall(msg)

    # Step 2: their version message
    msg = read_msg(stream)

    # Step 3: their verack message
    msg = read_msg(stream)

    # Step 4: our verack
    msg = serialize_msg(command=b"verack")
    sock.sendall(msg)

    return sock


def fetch_addresses():
    addresses = []
    for dns_seed in DNS_SEEDS:
        try:
            addr_info = socket.getaddrinfo(dns_seed, 0, 0, 0, 0)
            new_addresses = [(ai[-1][0], 8333) for ai in addr_info]
            addresses.extend(list(set(new_addresses)))
        except:
            logger.info(f"error fetching addresses from {dns_seed}")
            continue
    return addresses
