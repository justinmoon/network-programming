import socket
import time
import hashlib

from random import randint
from base64 import b32decode, b32encode
from pprint import pprint
from unittest import TestCase, TestSuite, TextTestRunner


NETWORK_MAGIC = b'\xf9\xbe\xb4\xd9'

# docs say it should be this but p2p network seems end b"\x00" x2
# IPV4_PREFIX = b"\x00" * 10 + b"\xff" * 2
IPV4_PREFIX = b"\x00" * 10 + b"\x00" * 2
ONION_PREFIX = b"\xFD\x87\xD8\x7E\xEB\x43"  # ipv6 prefix for .onion address
TIMEOUT = 5


def run(test):
    suite = TestSuite()
    suite.addTest(test)
    TextTestRunner().run(suite)


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


def compute_checksum(s):
    return double_sha256(s)[:4]


def hash160(s):
    return hashlib.new('ripemd160', hashlib.sha256(s).digest()).digest()


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


def serialize_varint(i):
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


def serialize_varstr(s):
    length = len(s)
    return serialize_varint(length) + s


def bytes_to_bool(bytes):
    return bool(little_endian_to_int(bytes))


###################
# Deserialization #
###################


def read_address(stream, has_timestamp):
    r = {}
    if has_timestamp:
        r["timestamp"] = little_endian_to_int(stream.read(4))
    r["services"] = little_endian_to_int(stream.read(8))
    r["ip"] = bytes_to_ip(stream.read(16))
    r["port"] = big_endian_to_int(stream.read(2))
    return r


def read_version_payload(stream):
    r = {}
    r["version"] = little_endian_to_int(stream.read(4))
    r["services"] = little_endian_to_int(stream.read(8))
    r["timestamp"] = little_endian_to_int(stream.read(8))
    r["receiver_address"] = read_address(stream, has_timestamp=False)
    r["sender_address"] = read_address(stream, has_timestamp=False)
    r["nonce"] = little_endian_to_int(stream.read(8))
    r["user_agent"] = stream.read(read_varint(stream))
    r["start_height"] = little_endian_to_int(stream.read(4))
    r["relay"] = bytes_to_bool(stream.read(1))
    return r


def read_empty_payload(stream):
    return {}


def read_addr_payload(stream):
    r = {}
    count = read_varint(stream)
    r["addresses"] = [read_address(stream, has_timestamp=False) 
                      for _ in range(count)]
    return r


def read_payload(command, stream):
    command_to_handler = {
        b"version": read_version_payload,
        b"verack": read_empty_payload,
        b"addr": read_addr_payload,
    }
    handler = command_to_handler[command]
    return handler(stream)


def read_message(stream):
    msg = {}
    magic = stream.read(4)
    if magic != NETWORK_MAGIC:
        raise Exception(f'Magic is wrong: {magic}')
    msg['command'] = stream.read(12).strip(b'\x00')
    payload_length = int.from_bytes(stream.read(4), 'little')
    checksum = stream.read(4)
    msg['payload'] = stream.read(payload_length)
    calculated_checksum = double_sha256(msg['payload'])[:4]
    if calculated_checksum != checksum:
        raise Exception('Checksum does not match')
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
        start_height=0, relay=True):
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
    result += serialize_varint(len(user_agent))
    result += user_agent
    result += int_to_little_endian(start_height, 4)
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
    msg = read_message(stream)
    print("Version: ")
    pprint(msg)

    # Step 3: their version message
    msg = read_message(stream)
    print("Verack: ", msg)

    # Step 4: our verack
    msg = serialize_msg(command=b"verack")
    sock.sendall(msg)
    print("Sent verack")

    return sock


def bits_to_target_initial(bits):
    '''Turns bits into a target (large 256-bit integer)'''
    # last byte is exponent
    # the first three bytes are the coefficient in little endian
    # the formula is:
    # coefficient * 256**(exponent-3)
    raise NotImplementedError()


def bits_to_target(bits):
    '''Turns bits into a target (large 256-bit integer)'''
    # last byte is exponent
    exponent = bits[-1]
    # the first three bytes are the coefficient in little endian
    coefficient = little_endian_to_int(bits[:-1])
    # the formula is:
    # coefficient * 256**(exponent-3)
    return coefficient * 256**(exponent - 3)


def target_to_bits(target):
    '''Turns a target integer back into bits, which is 4 bytes'''
    raw_bytes = target.to_bytes(32, 'big')
    # get rid of leading 0's
    raw_bytes = raw_bytes.lstrip(b'\x00')
    if raw_bytes[0] > 0x7f:
        # if the first bit is 1, we have to start with 00
        exponent = len(raw_bytes) + 1
        coefficient = b'\x00' + raw_bytes[:2]
    else:
        # otherwise, we can show the first 3 bytes
        # exponent is the number of digits in base-256
        exponent = len(raw_bytes)
        # coefficient is the first 3 digits of the base-256 number
        coefficient = raw_bytes[:3]
    # we've truncated the number after the first 3 digits of base-256
    new_bits = coefficient[::-1] + bytes([exponent])
    return new_bits


def merkle_parent(hash1, hash2):
    '''Takes the binary hashes and calculates the double_sha256'''
    # return the double_sha256 of hash1 + hash2
    return double_sha256(hash1 + hash2)


def merkle_parent_level(hashes):
    '''Takes a list of binary hashes and returns a list that's half
    the length'''
    # if the list has exactly 1 element raise an error
    if len(hashes) == 1:
        raise RuntimeError('Cannot take a parent level with only 1 item')
    # if the list has an odd number of elements, duplicate the last one
    # and put it at the end so it has an even number of elements
    if len(hashes) % 2 == 1:
        hashes.append(hashes[-1])
    # initialize next level
    parent_level = []
    # loop over every pair (use: for i in range(0, len(hashes), 2))
    for i in range(0, len(hashes), 2):
        # get the merkle parent of the hashes at index i and i+1
        parent = merkle_parent(hashes[i], hashes[i + 1])
        # append parent to parent level
        parent_level.append(parent)
    # return parent level
    return parent_level


def merkle_root(hashes):
    '''Takes a list of binary hashes and returns the merkle root
    '''
    # current level starts as hashes
    current_level = hashes
    # loop until there's exactly 1 element
    while len(current_level) > 1:
        # current level becomes the merkle parent level
        current_level = merkle_parent_level(current_level)
    # return the 1st item of the current level
    return current_level[0]

class LibraryTest(TestCase):

    def test_bits_to_target(self):
        expected_target = 26959535291011309493156476344723991336010898738574164086137773096960
        calculated_target = bits_to_target(b'\xff\xff\x00\x1d')
        self.assertEqual(expected_target, calculated_target)
        
    def test_merkle_parent(self):
        tx_hash0 = bytes.fromhex('c117ea8ec828342f4dfb0ad6bd140e03a50720ece40169ee38bdc15d9eb64cf5')
        tx_hash1 = bytes.fromhex('c131474164b412e3406696da1ee20ab0fc9bf41c8f05fa8ceea7a08d672d7cc5')
        want = bytes.fromhex('8b30c5ba100f6f2e5ad1e2a742e5020491240f8eb514fe97c713c31718ad7ecd')
        self.assertEqual(merkle_parent(tx_hash0, tx_hash1), want)

    def test_merkle_parent_level(self):
        hex_hashes = [
            'c117ea8ec828342f4dfb0ad6bd140e03a50720ece40169ee38bdc15d9eb64cf5',
            'c131474164b412e3406696da1ee20ab0fc9bf41c8f05fa8ceea7a08d672d7cc5',
            'f391da6ecfeed1814efae39e7fcb3838ae0b02c02ae7d0a5848a66947c0727b0',
            '3d238a92a94532b946c90e19c49351c763696cff3db400485b813aecb8a13181',
            '10092f2633be5f3ce349bf9ddbde36caa3dd10dfa0ec8106bce23acbff637dae',
            '7d37b3d54fa6a64869084bfd2e831309118b9e833610e6228adacdbd1b4ba161',
            '8118a77e542892fe15ae3fc771a4abfd2f5d5d5997544c3487ac36b5c85170fc',
            'dff6879848c2c9b62fe652720b8df5272093acfaa45a43cdb3696fe2466a3877',
            'b825c0745f46ac58f7d3759e6dc535a1fec7820377f24d4c2c6ad2cc55c0cb59',
            '95513952a04bd8992721e9b7e2937f1c04ba31e0469fbe615a78197f68f52b7c',
            '2e6d722e5e4dbdf2447ddecc9f7dabb8e299bae921c99ad5b0184cd9eb8e5908',
        ]
        tx_hashes = [bytes.fromhex(x) for x in hex_hashes]
        want_hex_hashes = [
            '8b30c5ba100f6f2e5ad1e2a742e5020491240f8eb514fe97c713c31718ad7ecd',
            '7f4e6f9e224e20fda0ae4c44114237f97cd35aca38d83081c9bfd41feb907800',
            'ade48f2bbb57318cc79f3a8678febaa827599c509dce5940602e54c7733332e7',
            '68b3e2ab8182dfd646f13fdf01c335cf32476482d963f5cd94e934e6b3401069',
            '43e7274e77fbe8e5a42a8fb58f7decdb04d521f319f332d88e6b06f8e6c09e27',
            '1796cd3ca4fef00236e07b723d3ed88e1ac433acaaa21da64c4b33c946cf3d10',
        ]
        want_tx_hashes = [bytes.fromhex(x) for x in want_hex_hashes]
        self.assertEqual(merkle_parent_level(tx_hashes), want_tx_hashes)

    def test_merkle_root(self):
        hex_hashes = [
            'c117ea8ec828342f4dfb0ad6bd140e03a50720ece40169ee38bdc15d9eb64cf5',
            'c131474164b412e3406696da1ee20ab0fc9bf41c8f05fa8ceea7a08d672d7cc5',
            'f391da6ecfeed1814efae39e7fcb3838ae0b02c02ae7d0a5848a66947c0727b0',
            '3d238a92a94532b946c90e19c49351c763696cff3db400485b813aecb8a13181',
            '10092f2633be5f3ce349bf9ddbde36caa3dd10dfa0ec8106bce23acbff637dae',
            '7d37b3d54fa6a64869084bfd2e831309118b9e833610e6228adacdbd1b4ba161',
            '8118a77e542892fe15ae3fc771a4abfd2f5d5d5997544c3487ac36b5c85170fc',
            'dff6879848c2c9b62fe652720b8df5272093acfaa45a43cdb3696fe2466a3877',
            'b825c0745f46ac58f7d3759e6dc535a1fec7820377f24d4c2c6ad2cc55c0cb59',
            '95513952a04bd8992721e9b7e2937f1c04ba31e0469fbe615a78197f68f52b7c',
            '2e6d722e5e4dbdf2447ddecc9f7dabb8e299bae921c99ad5b0184cd9eb8e5908',
            'b13a750047bc0bdceb2473e5fe488c2596d7a7124b4e716fdd29b046ef99bbf0',
        ]
        tx_hashes = [bytes.fromhex(x) for x in hex_hashes]
        want_hex_hash = 'acbcab8bcc1af95d8d563b77d24c3d19b18f1486383d75a5085c4e86c86beed6'
        want_hash = bytes.fromhex(want_hex_hash)
        self.assertEqual(merkle_root(tx_hashes), want_hash)

