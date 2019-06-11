##############
### Lesson ###
##############

# Connect to ping pong server using Python

def ping(ip, port):
    sock = socket.socket()
    sock.connect((ip, port))
    sock.send(b"ping")
    return sock.recv(1024)

# fill in "start" and "stop indices for "checksum" field

start = 4 + 12 + 4
stop = start + 4
print('4 "checksum" bytes:', VERSION[start:stop])

# Check Network Magic

def read_message(stream):
    magic = stream.read(4)
    ...

# Which is a testnet message, which is a mainnet message?

# m1 is a mainnet message, m2 is a testnet message.
# compare the "magic" values against those in the wiki
# to see why: https://en.bitcoin.it/wiki/Protocol_documentation#Message_structure

# Modify `lib.read_message` to raise a `RuntimeError` if the magic bytes are wrong

def read_message(stream):
    magic = stream.read(4)
    if magic != NETWORK_MAGIC:
        raise RuntimeError("bad magic")
    ...

# Interpret command

def read_message(stream):
    ...
    command = stream.read(12).strip(b"\x00")
    ...

# Have `read_message` read `length` and interpret it as an integer 

def read_message(stream):
    ...
    length = int.from_bytes(stream.read(4), "little")
    ...

# Have `read_message` read the `checksum`

def read_message(stream):
    ...
    checksum = stream.read(4)
    ...

# Have `read_message` read the `payload`

def read_message(stream):
    ...
    length = int.from_bytes(stream.read(4), "little")
    ...
    payload = stream.read(length)
    ...

# Implement `double_sha256` in [lib.py](./lib.py) which runs `sha256` twice on input and return `bytes` as output

def double_sha256(b):
    round_one = sha256(b).digest()
    round_two = sha256(round_one).digest()
    return round_two


# Have `read_message` calculate a checksum and raise a `RuntimeError` it it doesn't match the checksum on the message

def read_message(stream):
    ...
    length = int.from_bytes(stream.read(4), "little")
    checksum = stream.read(4)
    payload = stream.read(length)
    if checksum != double_sha256(payload)[:4]:
        raise RuntimeError("bad checksum")
    ...


# Complete `read_message` function

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
