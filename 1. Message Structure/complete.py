from hashlib import sha256

def little_endian_to_int(b):
    return int.from_bytes(b, 'little')

def hash256(b):
    return sha256(sha256(b).digest()).digest()

class NetworkEnvelope:

    def __init__(self, command, payload):
        self.command = command
        self.payload = payload

    @classmethod
    def from_stream(cls, stream):
        magic = stream.read(4)
        if magic != NETWORK_MAGIC:
            raise ValueError('Network magic is wrong')

        command = stream.read(12).strip(b"\x00")
        payload_length = little_endian_to_int(stream.read(4))
        checksum = stream.read(4)
        payload = stream.read(payload_length)

        if checksum != calculate_checksum(payload):
            raise RuntimeError("Checksums don't match")

        return cls(command, payload)

    def serialize(self):
        raise NotImplementedError()

    def __repr__(self):
        return f"<Message command={self.command}>"
