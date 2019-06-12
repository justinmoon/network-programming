from hashlib import sha256
from io import BytesIO

import pytest

NETWORK_MAGIC = b"\xf9\xbe\xb4\xd9"
TESTNET_MAGIC = b"\x0b\x11\x09\x07"
VERSION = b"\xf9\xbe\xb4\xd9version\x00\x00\x00\x00\x00f\x00\x00\x00!\xc4K\xd1\x7f\x11\x01\x00\r\x04\x00\x00\x00\x00\x00\x00C\xfc\xff\\\x00\x00\x00\x00\x0f\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\r\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x008\xb9\xf8*t\xba`\xec\x10/Satoshi:0.17.1/\xb9\xda\x08\x00\x01"
VERACK = b"\xf9\xbe\xb4\xd9verack\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00]\xf6\xe0\xe2"


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


def read_version_payload(stream):
    r = {}
    r["version"] = None
    r["services"] = None
    r["timestamp"] = None
    r["receiver_address"] = None
    r["sender_address"] = None
    r["nonce"] = None
    r["user_agent"] = read_varstr
    r["start_height"] = None
    r["relay"] = None
    return r


def little_endian_to_int(b):
    return int.from_bytes(b, "little")


def read_varint(s):
    i = s.read(1)[0]
    if i == 0xFD:
        # 0xfd means the next two bytes are the number
        return little_endian_to_int(s.read(2))
    elif i == 0xFE:
        # 0xfe means the next four bytes are the number
        return little_endian_to_int(s.read(4))
    elif i == 0xFF:
        # 0xff means the next eight bytes are the number
        return little_endian_to_int(s.read(8))
    else:
        # anything else is just the integer
        return i


def read_varstr(s):
    length = read_varint(s)
    string = s.read(length)
    return string
