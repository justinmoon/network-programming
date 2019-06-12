import socket
from hashlib import sha256
from io import BytesIO

import pytest

from complete.lib import read_varstr as magic_read_varstr
from utils import assert_len, check_field

NETWORK_MAGIC = b"\xf9\xbe\xb4\xd9"
TESTNET_MAGIC = b"\x0b\x11\x09\x07"
VERSION = b"\xf9\xbe\xb4\xd9version\x00\x00\x00\x00\x00f\x00\x00\x00!\xc4K\xd1\x7f\x11\x01\x00\r\x04\x00\x00\x00\x00\x00\x00C\xfc\xff\\\x00\x00\x00\x00\x0f\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\r\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x008\xb9\xf8*t\xba`\xec\x10/Satoshi:0.17.1/\xb9\xda\x08\x00\x01"
VERSION_PAYLOAD = b"\x7f\x11\x01\x00\r\x04\x00\x00\x00\x00\x00\x0028j\\\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xffFqPG\xa8\xc6\r\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00!\xf8\xe8\xff\xceL+s\x10/Satoshi:0.16.3/U\x99\x08\x00\x01"  # FIXME
VERACK = b"\xf9\xbe\xb4\xd9verack\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00]\xf6\xe0\xe2"
IPV4_PREFIX = b"\x00" * 10 + b"\xff" * 2


def read_message(stream):
    magic = stream.read(4)
    if magic != NETWORK_MAGIC:
        raise RuntimeError("bad magic")
    command = stream.read(12).strip(b"\x00")
    length = int.from_bytes(stream.read(4), "little")
    checksum = stream.read(4)
    payload = stream.read(length)
    if checksum != double_sha256(payload)[:4]:
        raise RuntimeError("bad checksum")
    return {"command": command, "payload": payload}


def double_sha256(b):
    round_one = sha256(b).digest()
    round_two = sha256(round_one).digest()
    return round_two


def bytes_to_bool(bytes):
    raise NotImplementedError()


def test_bytes_to_bool():
    assert (
        bytes_to_bool(b"\x00") is False
    ), f'bytes_to_bool(b"\x00") should return False'
    assert bytes_to_bool(b"\x00") is False, f'bytes_to_bool(b"\x01") should return True'


def little_endian_to_int(b):
    raise NotImplementedError()


def test_little_endian_to_int():
    i = 22
    bytes = int.to_bytes(22, 10, "little")
    result = little_endian_to_int(bytes)
    assert i == result, f"Correct answer: {i}. Your answer: {result}"


def big_endian_to_int(b):
    raise NotImplementedError()


def test_big_endian_to_int():
    i = 1_000_000
    bytes = int.to_bytes(i, 7, "big")
    result = big_endian_to_int(bytes)
    assert i == result, f"Correct answer: {i}. Your answer: {result}"


def bytes_to_ip(b):
    raise NotImplementedError()


def test_bytes_to_ip():
    ipv4_bytes = b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff\n\x00\x00\x01"
    assert bytes_to_ip(ipv4_bytes) == "10.0.0.1"
    ipv6_bytes = b"\xfe\x80\x00\x00\x00\x00\x00\x00\x02\x02\xb3\xff\xfe\x1e\x83)"
    assert bytes_to_ip(ipv6_bytes) == "fe80::202:b3ff:fe1e:8329"


def read_address(stream, has_timestamp):
    r = {}
    if has_timestamp:
        r["timestamp"] = ...
    r["services"] = ...
    r["ip"] = ...
    r["port"] = ...
    return r


def test_read_address():
    services = 7
    services_bytes = services.to_bytes(8, "little")
    ipv4 = "10.0.10.0"
    ipv4_bytes = IPV4_PREFIX + socket.inet_pton(socket.AF_INET, ipv4)
    ipv6 = "2a02:1205:501e:d30:f57a:6958:7e47:2694"
    ipv6_bytes = socket.inet_pton(socket.AF_INET6, ipv6)
    port = 8333
    port_bytes = port.to_bytes(2, "big")

    # IPv4
    stream = BytesIO(services_bytes + ipv4_bytes + port_bytes)
    address = read_address(stream, has_timestamp=False)
    assert address["services"] == services
    assert address["ip"] == ipv4
    assert address["port"] == port

    # IPv6
    stream = BytesIO(services_bytes + ipv6_bytes + port_bytes)
    address = read_address(stream, has_timestamp=False)
    assert address["ip"] == ipv6


def read_varint(stream):
    i = little_endian_to_int(stream.read(1))
    if i == 0xFF:
        return little_endian_to_int(stream.read(1))
    elif i == 0xFE:
        return "FIXME"
    elif "FIXME":
        return "FIXME"
    else:
        "FIXME"


def test_read_varint():
    # FIXME: Ungodly amount of test code ...
    eight_byte_int = 2 ** (8 * 8) - 1
    four_byte_int = 2 ** (8 * 4) - 1
    two_byte_int = 2 ** (8 * 2) - 1
    one_byte_int = 7

    eight_byte_int_bytes = eight_byte_int.to_bytes(8, "little")
    four_byte_int_bytes = four_byte_int.to_bytes(4, "little")
    two_byte_int_bytes = two_byte_int.to_bytes(2, "little")
    one_byte_int_bytes = one_byte_int.to_bytes(1, "little")

    eight_byte_prefix = (0xFF).to_bytes(1, "little")
    four_byte_prefix = (0xFE).to_bytes(1, "little")
    two_byte_prefix = (0xFD).to_bytes(1, "little")

    eight_byte_var_int = eight_byte_prefix + eight_byte_int_bytes
    four_byte_var_int = four_byte_prefix + four_byte_int_bytes
    two_byte_var_int = two_byte_prefix + two_byte_int_bytes
    one_byte_var_int = one_byte_int_bytes

    enumerated = (
        (eight_byte_int, eight_byte_var_int),
        (four_byte_int, four_byte_var_int),
        (two_byte_int, two_byte_var_int),
        (one_byte_int, one_byte_var_int),
    )
    for correct_int, var_int in enumerated:
        stream = BytesIO(var_int)
        calculated_int = read_varint(stream)
        assert correct_int == calculated_int, (correct_int, calculated_int)


def read_varstr(stream):
    raise NotImplementedError()


def test_read_varstr():
    long_str = b"A purely peer-to-peer version of electronic cash would allow online payments to be sent directly from one party to another without going through a financial institution. Digital signatures provide part of the solution, but the main benefits are lost if a trusted third party is still required to prevent double-spending. We propose a solution to the double-spending problem using a peer-to-peer network.  The network timestamps transactions by hashing them into an ongoing chain of hash-based proof-of-work, forming a record that cannot be changed without redoing the proof-of-work. The longest chain not only serves as proof of the sequence of events witnessed, but proof that it came from the largest pool of CPU power. As long as a majority of CPU power is controlled by nodes that are not cooperating to attack the network, they'll generate the longest chain and outpace attackers. The network itself requires minimal structure. Messages are broadcast on a best effort basis, and nodes can leave and rejoin the network at will, accepting the longest proof-of-work chain as proof of what happened while they were gone."
    long_var_str = b"\xfda\x04" + long_str
    short_str = b"!"
    short_var_str = b"\x01" + short_str
    enumerated = ((short_str, short_var_str), (long_str, long_var_str))
    for correct_byte_str, var_str in enumerated:
        stream = BytesIO(var_str)
        calculated_byte_str = read_varstr(stream)
        assert correct_byte_str == calculated_byte_str
    print("Test passed!")


def read_version_payload(stream):
    r = {}
    r["version"] = None
    r["services"] = None
    r["timestamp"] = None
    r["receiver_address"] = None
    r["sender_address"] = None
    r["nonce"] = None
    r["user_agent"] = magic_read_varstr(stream)
    r["start_height"] = None
    r["relay"] = None
    return r


def test_read_version_payload_initial():
    version_payload = read_message(BytesIO(VERSION))["payload"]
    payload = read_version_payload(BytesIO(version_payload))

    # Dictionary keys
    observed_keys = set(payload.keys())
    expected_keys = set(
        [
            "version",
            "services",
            "timestamp",
            "receiver_address",
            "sender_address",
            "nonce",
            "user_agent",
            "start_height",
            "relay",
        ]
    )
    missing_keys = expected_keys - observed_keys
    extra_keys = observed_keys - expected_keys

    assert not missing_keys, f"The following keys were missing: {missing_keys}"
    assert not extra_keys, f"Encountered unexpected key(s): {extra_keys}"

    # Dictionary values
    assert_len(payload, "version", 4)
    assert_len(payload, "services", 8)
    assert_len(payload, "timestamp", 8)
    assert_len(payload, "receiver_address", 26)
    assert_len(payload, "sender_address", 26)
    assert_len(payload, "nonce", 8)
    assert_len(payload, "start_height", 4)
    assert_len(payload, "relay", 1)

    print("Test passed!")


def test_read_version_payload_integer_fields():
    stream = BytesIO(VERSION_PAYLOAD)
    payload = read_version_payload(stream)

    check_field(payload, "version", b"\x7f\x11\x01\x00", 70015)
    check_field(payload, "services", b"\r\x04\x00\x00\x00\x00\x00\x00", 1037)
    check_field(payload, "timestamp", b"28j\\\x00\x00\x00\x00", 1550465074)
    check_field(payload, "nonce", b"!\xf8\xe8\xff\xceL+s", 8298811190300702753)
    check_field(payload, "start_height", b"U\x99\x08\x00", 563541)


def test_read_version_payload_boolean_fields():
    stream = BytesIO(VERSION_PAYLOAD)
    payload = read_version_payload(stream)
    assert payload["relay"] is True

    stream = BytesIO(VERSION_PAYLOAD[:-1] + b"\x00")
    payload = read_version_payload(stream)
    assert payload["relay"] is False


def test_read_version_payload_varstr():
    stream = BytesIO(VERSION_PAYLOAD)
    payload = read_version_payload(stream)
    assert payload["user_agent"] == b"/Satoshi:0.16.3/"


def test_read_version_payload_final():
    vp = read_version_payload(BytesIO(VERSION_PAYLOAD))
    assert vp["version"] == 70015
    assert vp["services"] == 1037
    assert vp["timestamp"] == 1550465074
    assert vp["receiver_address"] == {
        "services": 0,
        "ip": "70.113.80.71",
        "port": 43206,
    }
    assert vp["sender_address"] == {"services": 1037, "ip": "::", "port": 0}
    assert vp["nonce"] == 8298811190300702753
    assert vp["user_agent"] == b"/Satoshi:0.16.3/"
    assert vp["start_height"] == 563541
    assert vp["relay"] == 1
