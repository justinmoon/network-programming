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
    return {
        "magic": magic,
        "command": command,
        "length": length,
        "checksum": checksum,
        "payload": payload,
    }


def test_read_magic():
    mainnet = read_message(BytesIO(VERSION))
    assert (
        mainnet["magic"] == NETWORK_MAGIC
    ), f'"magic" key should be {NETWORK_MAGIC}, was {mainnet["magic"]}'
    testnet = read_message(BytesIO(TESTNET_MAGIC + VERSION[4:]))
    assert (
        testnet["magic"] == TESTNET_MAGIC
    ), f'"magic" key should be {TESTNET_MAGIC}, was {testnet["magic"]}'


def test_bad_magic():
    # rewrite the magic with empty bytes and check RuntimeError is raised
    raw = b"\x00" * 4 + VERSION[4:]
    with pytest.raises(RuntimeError):
        read_message(BytesIO(raw))


def test_command():
    version = read_message(BytesIO(VERSION))
    assert (
        version["command"] == b"version"
    ), f'"command" key should be b"version", was {version["command"]}'
    verack = read_message(BytesIO(VERACK))
    assert (
        verack["command"] == b"verack"
    ), f'"command" key should be b"verack", was {version["command"]}'


def test_length():
    stream = BytesIO(VERSION)
    length = read_message(stream)["length"]
    assert length == 102, f"length should be 102, was {length}"


def test_checksum():
    stream = BytesIO(VERSION)
    assert read_message(stream)["checksum"] == b"!\xc4K\xd1"


def test_read_payload():
    stream = BytesIO(VERSION + b"x")
    msg = read_message(stream)
    assert len(msg["payload"]) == msg["length"]
    assert stream.read(1) == b"x"


def test_bad_checksum():
    # overwrite the checksum w/ zero bytes
    raw = VERSION[:20] + b"\x00" * 4 + VERSION[24:]
    with pytest.raises(RuntimeError):
        read_message(BytesIO(raw))


def double_sha256(b):
    round_one = sha256(b).digest()
    round_two = sha256(round_one).digest()
    return round_two


def test_double_sha256():
    assert (
        double_sha256(b"don't trust, verify")
        == b"\xdf\xdbf\x95\x14\x98|45\xda6\x1em\x06y\xc9\xee@\x85\xa5\xca\x1d\xaa\xa1.\xf9\t\x91\x9c\xc1\xa7\xf0"
    )
