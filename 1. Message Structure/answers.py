# Ex 1: Ping-Pong

import socket

sock = socket.socket()
sock.connect(("68.183.109.101", 10000))
sock.send(b"ping")
response = sock.recv(1024)
print("Response: ", response)

# Ex 2: Spotting mainnet & testnet messages

def is_mainnet_msg(stream):
    magic = read_magic(stream)
    return magic == b"\xf9\xbe\xb4\xd9"

def is_testnet_msg(stream):
    magic = read_magic(stream)
    return magic == b"\x0b\x11\x09\x07"

# Ex 3: Spotting version & verack messages

def read_command(stream):
    raw = stream.read(12)
    command = raw.replace(b"\x00", b"")  # remove empty byte padding
    return command
    
def is_version_msg(stream):
    command = read_command(stream)
    return command == b"version"
    
def is_verack_msg(stream):
    command = read_command(stream)
    return "FIXME"

# Ex x: little lndian to int

def little_endian_to_int(b):
    return int.from_bytes(b, 'little')



################
### Homework ###
################


class NetworkEnvelope:

    def __init__(self, command, payload):
        self.command = command
        self.payload = payload

    @classmethod
    def from_stream(cls, stream):
        magic = stream.read(4)
        if magic != NETWORK_MAGIC:
            raise RuntimeError('Network magic is wrong')

        command = stream.read(12).strip(b"\x00")
        payload_length = int.from_bytes(stream.read(4), 'little')
        checksum = stream.read(4)
        payload = stream.read(payload_length)

        if checksum != calculate_checksum(payload):
            raise RuntimeError("Checksums don't match")

        return cls(command, payload)

    def serialize(self):
        raise NotImplementedError()

    def __repr__(self):
        return f"<Message command={self.command}>"

