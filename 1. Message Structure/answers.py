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

# Ex 4: Read message length

def read_length(stream):
    raw = stream.read(4)
    length = int.from_bytes(raw, 'little')
    return length

# Ex 5: Read checksum

def read_checksum(stream):
    return stream.read(4)

# Ex 6: Read payload

def read_payload(stream, length):
    return stream.read(length)

# Ex 7: Double SHA256

def hash256(b):
    first_round = sha256(b).digest()
    second_round = sha256(first_round).digest()
    return second_round

# Ex 8: Compute checksum

def compute_checksum(b):
    hashed = hash256(b)
    first_four_bytes = hashed[:4]
    return first_four_bytes

# Ex 9: Bad magic throws error

def read_message(stream):
    magic = read_magic(stream)
    if magic != NETWORK_MAGIC:
        raise RuntimeError('Network magic is wrong')
    command = read_command(stream)
    length = read_length(stream)
    checksum = read_checksum(stream)
    payload = read_payload(stream, length)
    return command, payload

# Ex 10: Bad checksum throws error

def read_message(stream):
    magic = read_magic(stream)
    if magic != NETWORK_MAGIC:
        raise RuntimeError('Network magic is wrong')
    command = read_command(stream)
    length = read_length(stream)
    checksum = read_checksum(stream)
    payload = read_payload(stream, length)
    if checksum != compute_checksum(payload):
        raise RuntimeError("Checksums don't match")
    return command, payload

# Ex 11: The final `NetworkEnvelope` class

class NetworkEnvelope:

    def __init__(self, command, payload):
        self.command = command
        self.payload = payload

    @classmethod
    def from_stream(cls, stream):
        magic = read_magic(stream)
        if magic != NETWORK_MAGIC:
            raise RuntimeError('Network magic is wrong')
        command = read_command(stream)
        length = read_length(stream)
        checksum = read_checksum(stream)
        payload = read_payload(stream, length)
        if checksum != compute_checksum(payload):
            raise RuntimeError("Checksums don't match")
        return cls(command, payload)

    def __repr__(self):
        return f"<Message command={self.command}>"

################
### Homework ###
################


