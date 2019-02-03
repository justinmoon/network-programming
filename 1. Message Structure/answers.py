
##############
### Lesson ###
##############

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

###
### `bites` -> `int`
###

# Step 1: decimal_places_to_int

def decimal_places_to_int(places):
    total = 0
    for exponent, coefficient in enumerate(reversed(places)):
        total += coefficient * 10 ** exponent
    return total

# Step 2: base_256_places_to_int

def base_256_places_to_int(places):
    total = 0
    for exponent, coefficient in enumerate(reversed(places)):
        total += coefficient * 256 ** exponent
    return total

# Step 3: places_to_int(places, base)

def places_to_int(places, base):
    total = 0
    for exponent, coefficient in enumerate(reversed(places)):
        total += coefficient * base ** exponent
    return total

# Step 4: places_to_int(places, base, byte_order)

def places_to_int(places, base, byte_order):
    if byte_order not in ['little', 'big']:
        raise ValueError("Invalid byte order")
    total = 0
    if byte_order == 'big':
        places = reversed(places)
    for exponent, coefficient in enumerate(places):
        total += coefficient * base ** exponent
    return total

# Step 5: bites.to_int(base, byte_order)

class bites:

    def __init__(self, values):
        self.values = values

    def __repr__(self):
        return "(cheating) " + repr(self.values)

    def to_int(self, byte_order):
        return places_to_int(self.values, 256, byte_order)

    @classmethod
    def from_int(cls, n, length, byte_order):
        raise NotImplementedError()

###
### `int` -> `bites`
###

# get_ones_place()

def get_ones_place():
    return N % 256

# get_65536s_place()

def get_65536s_place():
    return N // 256 // 256 % 256

# Step 1: int_to_base_256_places(n)

# TODO: give them this hint

def int_to_base_256_places(n):
    places = []
    while n > 0:
        places.insert(0, "FIXME")
        n = "FIXME"
    return places

# Then this answer

def int_to_base_256_places(n):
    places = []
    while n > 0:
        places.insert(0, n % 256)
        n = n // 256
    return places

# Step 2: int_to_places(n, base)

def int_to_places(n, base):
    places = []
    while n > 0:
        places.insert(0, n % base)
        n = n // base
    return places

# Step 3: int_to_places(n, base, length)

def int_to_places(n, base, length):
    places = []
    while len(places) < length:
        places.insert(0, n % base)
        n = n // base
    if n != 0:
        raise ValueError("Doesn't fit")
    return places

# Step 4: int_to_places(n, base, length, byte_order)

def int_to_places(n, base, length, byte_order):
    if byte_order not in ['little', 'big']:
        raise ValueError("Invalid byte order")
    places = []
    while len(places) < length:
        places.insert(0, n % base)
        n = n // base
    if n != 0:
        raise ValueError("Doesn't fit")
    if byte_order == "little":
        places.reverse()
    return places

# Step 5: bites.from_int(n, length, byte_order)

class bites:

    def __init__(self, values):
        self.values = values

    def __repr__(self):
        return "(cheating) " + repr(self.values)

    def to_int(self, byte_order):
        return places_to_int(self.values, 256, byte_order)

    @classmethod
    def from_int(cls, n, length, byte_order):
        places = int_to_places(n, 256, length, byte_order)
        return cls(places)

###
### `bites.__repr__`
###

# represent()

# Hint

def represent(b):
    result = ""
    for n in b.values:
        if n in special_chars:
            result += ?
        else:
            result += ?
    return result

# Answer

def represent(b):
    result = ""
    for n in b.values:
        if n in special_chars:
            result += special_chars[n]
        else:
            result += '\\x' + f"{n:02x}"
    return result

# `bites.__repr__`

class bites:

    def __init__(self, values):
        self.values = values

    def __eq__(self, other):
        return self.values == other.values

    def __repr__(self):
        result = ""
        for n in self.values:
            if n in special_chars:
                result += special_chars[n]
            else:
                result += '\\x' + hex(n)[2:]
        return result

    def to_int(self, byte_order):
        return places_to_int(self.values, 256, byte_order)

    @classmethod
    def from_int(cls, n, length, byte_order):
        places = int_to_places(n, 256, length, byte_order)
        return cls(places)

    def strip(self, pattern):
        return bites(list(bytes(self.values).strip(pattern)))
