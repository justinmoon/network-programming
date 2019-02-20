import socket
import time
import hashlib

from io import BytesIO
from random import randint
from base64 import b32decode, b32encode
from pprint import pprint


NETWORK_MAGIC = b'\xf9\xbe\xb4\xd9'

# docs say it should be this but p2p network seems end b"\x00" x2
# IPV4_PREFIX = b"\x00" * 10 + b"\xff" * 2
IPV4_PREFIX = b"\x00" * 10 + b"\x00" * 2
ONION_PREFIX = b"\xFD\x87\xD8\x7E\xEB\x43"  # ipv6 prefix for .onion address
TIMEOUT = 5


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
    if b[:6] == ONION_PREFIX:  # Tor
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


def read_varstr(s):
    length = read_varint(s)
    string = s.read(length)
    return string


def encode_varstr(s):
    length = len(s)
    return encode_varint(length) + s


###################
# Deserialization #
###################


def deserialize_address(stream, timestamp):
    r = {}
    if timestamp:
        r["time"] = little_endian_to_int(stream.read(4))
    r["services"] = little_endian_to_int(stream.read(8))
    r["ip"] = bytes_to_ip(stream.read(16))
    r["port"] = big_endian_to_int(stream.read(2))
    return r


def deserialize_version_payload(stream):
    r = {}
    r["version"] = little_endian_to_int(stream.read(4))
    r["services"] = little_endian_to_int(stream.read(8))
    r["timestamp"] = little_endian_to_int(stream.read(8))
    r["receiver_address"] = deserialize_address(stream, timestamp=False)
    r["sender_address"] = deserialize_address(stream, timestamp=False)
    r["nonce"] = little_endian_to_int(stream.read(8))
    r["user_agent"] = stream.read(read_varint(stream))
    r["latest_block"] = little_endian_to_int(stream.read(4))
    r["relay"] = little_endian_to_int(stream.read(1))
    return r


def deserialize_empty_payload(stream):
    return {}


def deserialize_addr_payload(stream):
    r = {}
    count = read_varint(stream)
    r["addresses"] = [deserialize_address(stream) for _ in range(count)]
    return r


def deserialize_payload(command, stream):
    command_to_handler = {
        b"version": deserialize_version_payload,
        b"verack": deserialize_empty_payload,
        b"addr": deserialize_addr_payload,
    }
    handler = command_to_handler[command]
    return handler(stream)


def deserialize_message(stream):
    """ payload attributes at top level """
    msg = {}
    magic = stream.read(4)
    if magic != NETWORK_MAGIC:
        raise Exception(f'Magic is wrong: {magic}')
    msg['command'] = stream.read(12).strip(b'\x00')
    payload_length = int.from_bytes(stream.read(4), 'little')
    checksum = stream.read(4)
    raw_payload = stream.read(payload_length)
    calculated_checksum = double_sha256(raw_payload)[:4]
    if calculated_checksum != checksum:
        raise Exception('Checksum does not match')
    msg['payload'] = deserialize_payload(msg['command'], BytesIO(raw_payload))
    return msg


#################
# Serialization #
#################


def serialize_version_payload(
        version=70015, services=0, timestamp=None,
        receiver_services=0,
        receiver_ip='0.0.0.0', receiver_port=8333,
        sender_services=0,
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


def serialize_empty_payload(**kwargs):
    return b""


def serialize_payload(**kwargs):
    command_to_handler = {
        b"version": serialize_version_payload,
        b"verack": serialize_empty_payload,
        b"getaddr": serialize_empty_payload,
    }
    command = kwargs.pop('command')
    handler = command_to_handler[command]
    return handler(**kwargs)


def serialize_msg(**kwargs):
    result = NETWORK_MAGIC
    command = kwargs['command']  # popping is weird ...
    result += command + b'\x00' * (12 - len(command))
    payload = serialize_payload(**kwargs)
    result += int_to_little_endian(len(payload), 4)
    result += double_sha256(payload)[:4]
    result += payload
    return result


##############
# Networking #
##############


def handshake(address):
    sock = socket.create_connection(address, TIMEOUT)
    stream = sock.makefile("rb")

    # Step 1: our version message
    msg = serialize_msg(command=b"version")
    sock.sendall(msg)
    print("Sent version")

    # Step 2: their version message
    msg = deserialize_message(stream)
    print("Version: ")
    pprint(msg)

    # Step 3: their version message
    msg = deserialize_message(stream)
    print("Verack: ", msg)

    # Step 4: our verack
    msg = serialize_msg(command=b"verack")
    sock.sendall(msg)
    print("Sent verack")

    return sock


def simple_crawler():
    addresses = [
        ("35.198.151.21", 8333),
        ("91.221.70.137", 8333),
        ("92.255.176.109", 8333),
        ("94.199.178.17", 8333),
    ]
    while addresses:
        start = time.time()
        address = addresses.pop()
        print('Connecting to ', address)

        # If we can't connect, proceed to next address
        try:
            sock = handshake(address)
        except Exception as e:
            print(f"Encountered error: {e}")
            raise
            continue

        # Save the address & version payload
        # TODO
        # observe_node(address, version_payload)

        stream = sock.makefile("rb")

        # Request their peer list
        sock.send(serialize_msg(command=b"getaddr"))

        print("Waiting for addr message")
        while True:
            # Only wait 5 seconds for addr message
            if time.time() - start > 5:
                break

            # If connection breaks, proceed to next address
            try:
                msg = deserialize_message(stream)
            except:
                break

            # Only handle "addr" messages
            if msg["command"] == b"addr":
                if len(msg["addresses"]) > 1:
                    addresses.extend([(a["ip"], a["port"])
                                      for a in msg["addresses"]])
                    print(f'Received {len(msg["addresses"])} addrs')
                    break
            else:
                print("ignoring ", msg["command"])
    print("Ran out of addresses. Exiting.")


if __name__ == '__main__':
    simple_crawler()
