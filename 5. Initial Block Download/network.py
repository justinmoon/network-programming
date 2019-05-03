import time

from io import BytesIO
from random import randint
from socket import create_connection
from unittest import TestCase

from lib import (
    double_sha256,
    serialize_varint,
    int_to_little_endian,
    little_endian_to_int,
    read_varint,
)
from block import BlockHeader, Block


NETWORK_MAGIC = b'\xf9\xbe\xb4\xd9'


class NetworkEnvelope:

    def __init__(self, command, payload):
        self.command = command
        self.payload = payload
        self.magic = NETWORK_MAGIC

    def __repr__(self):
        return '{}: {}'.format(
            self.command.decode('ascii'),
            self.payload.hex(),
        )

    @classmethod
    def parse(cls, s):
        '''Takes a stream and creates a NetworkEnvelope'''
        # check the network magic
        magic = s.read(4)
        if magic == b'':
            raise RuntimeError('Connection reset!')
        if magic != NETWORK_MAGIC:
            raise RuntimeError('magic is not right {} vs {}'.format(magic.hex(), NETWORK_MAGIC.hex()))
        # command 12 bytes
        command = s.read(12)
        # strip the trailing 0's
        command = command.strip(b'\x00')
        # payload length 4 bytes, little endian
        payload_length = little_endian_to_int(s.read(4))
        # checksum 4 bytes, first four of hash256 of payload
        checksum = s.read(4)
        # payload is of length payload_length
        payload = s.read(payload_length)
        # verify checksum
        calculated_checksum = double_sha256(payload)[:4]
        if calculated_checksum != checksum:
            raise RuntimeError('checksum does not match')
        # return an instance of the class
        return cls(command, payload)

    def serialize(self):
        '''Returns the byte serialization of the entire network message'''
        # add the network magic
        result = self.magic
        # command 12 bytes
        # fill with 0's
        result += self.command + b'\x00' * (12 - len(self.command))
        # payload length 4 bytes, little endian
        result += int_to_little_endian(len(self.payload), 4)
        # checksum 4 bytes, first four of hash256 of payload
        result += double_sha256(self.payload)[:4]
        # payload
        result += self.payload
        return result

    def stream(self):
        '''Returns a stream for parsing the payload'''
        return BytesIO(self.payload)


class VersionMessage:
    command = b'version'

    def __init__(self, version=70015, services=0, timestamp=None,
                 receiver_services=0,
                 receiver_ip=b'\x00\x00\x00\x00', receiver_port=8333,
                 sender_services=0,
                 sender_ip=b'\x00\x00\x00\x00', sender_port=8333,
                 nonce=None, user_agent=b'/programmingbitcoin:0.1/',
                 latest_block=0, relay=False):
        self.version = version
        self.services = services
        if timestamp is None:
            self.timestamp = int(time.time())
        else:
            self.timestamp = timestamp
        self.receiver_services = receiver_services
        self.receiver_ip = receiver_ip
        self.receiver_port = receiver_port
        self.sender_services = sender_services
        self.sender_ip = sender_ip
        self.sender_port = sender_port
        if nonce is None:
            self.nonce = int_to_little_endian(randint(0, 2**64), 8)
        else:
            self.nonce = nonce
        self.user_agent = user_agent
        self.latest_block = latest_block
        self.relay = relay

    def serialize(self):
        '''Serialize this message to send over the network'''
        # version is 4 bytes little endian
        result = int_to_little_endian(self.version, 4)
        # services is 8 bytes little endian
        result += int_to_little_endian(self.services, 8)
        # timestamp is 8 bytes little endian
        result += int_to_little_endian(self.timestamp, 8)
        # receiver services is 8 bytes little endian
        result += int_to_little_endian(self.receiver_services, 8)
        # IPV4 is 10 00 bytes and 2 ff bytes then receiver ip
        result += b'\x00' * 10 + b'\xff\xff' + self.receiver_ip
        # receiver port is 2 bytes, big endian
        result += self.receiver_port.to_bytes(2, 'big')
        # sender services is 8 bytes little endian
        result += int_to_little_endian(self.sender_services, 8)
        # IPV4 is 10 00 bytes and 2 ff bytes then sender ip
        result += b'\x00' * 10 + b'\xff\xff' + self.sender_ip
        # sender port is 2 bytes, big endian
        result += self.sender_port.to_bytes(2, 'big')
        # nonce should be 8 bytes
        result += self.nonce
        # useragent is a variable string, so varint first
        result += serialize_varint(len(self.user_agent))
        result += self.user_agent
        # latest block is 4 bytes little endian
        result += int_to_little_endian(self.latest_block, 4)
        # relay is 00 if false, 01 if true
        if self.relay:
            result += b'\x01'
        else:
            result += b'\x00'
        return result


class VersionMessageTest(TestCase):

    def test_serialize(self):
        v = VersionMessage(timestamp=0, nonce=b'\x00' * 8)
        self.assertEqual(v.serialize().hex(), '7f11010000000000000000000000000000000000000000000000000000000000000000000000ffff00000000208d000000000000000000000000000000000000ffff00000000208d0000000000000000182f70726f6772616d6d696e67626974636f696e3a302e312f0000000000')

class VerAckMessage:
    command = b'verack'

    def __init__(self):
        pass

    @classmethod
    def parse(cls, s):
        return cls()

    def serialize(self):
        return b''

class GetHeadersMessage:
    command = b'getheaders'

    def __init__(self, version=70015, num_hashes=1, start_block=None, end_block=None):
        self.version = version
        self.num_hashes = num_hashes
        if start_block is None:
            raise RuntimeError('a start block is required')
        self.start_block = start_block
        if end_block is None:
            self.end_block = b'\x00' * 32
        else:
            self.end_block = end_block

    def serialize(self):
        '''Serialize this message to send over the network'''
        # protocol version is 4 bytes little-endian
        # number of hashes is a varint
        # start block is in little-endian
        # end block is also in little-endian
        raise NotImplementedError()


class GetHeadersMessageTest(TestCase):

    def test_serialize(self):
        block_hex = '0000000000000000001237f46acddf58578a37e213d2a6edc4884a2fcad05ba3'
        gh = GetHeadersMessage(start_block=bytes.fromhex(block_hex))
        self.assertEqual(gh.serialize().hex(), '7f11010001a35bd0ca2f4a88c4eda6d213e2378a5758dfcd6af437120000000000000000000000000000000000000000000000000000000000000000000000000000000000')


class HeadersMessage:
    command = b'headers'

    def __init__(self, blocks):
        self.blocks = blocks

    @classmethod
    def parse(cls, stream):
        return stream.getvalue()


class HeadersMessageTest(TestCase):

    def test_parse(self):
        hex_msg = '0200000020df3b053dc46f162a9b00c7f0d5124e2676d47bbe7c5d0793a500000000000000ef445fef2ed495c275892206ca533e7411907971013ab83e3b47bd0d692d14d4dc7c835b67d8001ac157e670000000002030eb2540c41025690160a1014c577061596e32e426b712c7ca00000000000000768b89f07044e6130ead292a3f51951adbd2202df447d98789339937fd006bd44880835b67d8001ade09204600'
        stream = BytesIO(bytes.fromhex(hex_msg))
        headers_msg = HeadersMessage.parse(stream)
        self.assertEqual(len(headers_msg.headers), 2)
        for b in headers_msg.headers:
            self.assertEqual(b.__class__, BlockHeader)


class GetDataMessage:
    command = b'getdata'

    def __init__(self):
        self.data = []

    def add_block(self, identifier):
        # https://en.bitcoin.it/wiki/Protocol_documentation#Inventory_Vectors
        self.data.append((2, identifier))

    def serialize(self):
        # start with the number of items as a varint
        # loop through each tuple (data_type, identifier) in self.data
        # data type is 4 bytes Little-Endian
        # identifier needs to be in Little-Endian
        raise NotImplementedError()


class GetDataMessageTest(TestCase):

    def test_serialize(self):
        hex_msg = '020200000030eb2540c41025690160a1014c577061596e32e426b712c7ca00000000000000020000001049847939585b0652fba793661c361223446b6fc41089b8be00000000000000'
        get_data = GetDataMessage()
        block1 = bytes.fromhex('00000000000000cac712b726e4326e596170574c01a16001692510c44025eb30')
        get_data.add_block(block1)
        block2 = bytes.fromhex('00000000000000beb88910c46f6b442312361c6693a7fb52065b583979844910')
        get_data.add_block(block2)
        self.assertEqual(get_data.serialize().hex(), hex_msg)


class BlockMessage:
    command = b'block'

    def __init__(self, block):
        self.block = block

    @classmethod
    def parse(cls, stream):
        return stream.getvalue()


class BlockMessageTest(TestCase):

    def test_parse(self):
        raw_block_msg = bytes.fromhex('010000006fe28c0ab6f1b372c1a6a246ae63f74f931e8365e15a089c68d6190000000000982051fd1e4ba744bbbe680e1fee14677ba1a3c3540bf7b1cdb606e857233e0e61bc6649ffff001d01e362990101000000010000000000000000000000000000000000000000000000000000000000000000ffffffff0704ffff001d0104ffffffff0100f2052a0100000043410496b538e853519c726a2c91e61ec11600ae1390813a627c66fb8be7947be63c52da7589379515d4e0a604f8141781e62294721166bf621e73a82cbf2342c858eeac00000000')
        block_msg = BlockMessage.parse(BytesIO(raw_block_msg))
        self.assertEqual(len(block_msg.block.txns), 1)


class PingMessage:
    command = b'ping'

    def __init__(self, nonce):
        self.nonce = nonce

    @classmethod
    def parse(cls, s):
        nonce = s.read(8)
        return cls(nonce)

    def serialize(self):
        return self.nonce


class PongMessage:
    command = b'pong'

    def __init__(self, nonce):
        self.nonce = nonce

    def parse(cls, s):
        nonce = s.read(8)
        return cls(nonce)

    def serialize(self):
        return self.nonce


class PeerConnection:

    def __init__(self, host, port, logging=False):
        # create socket connection to peer
        self.socket = create_connection((host, port))
        # create a byte-stream from the socket connection
        self.stream = self.socket.makefile('rb')
        self.logging = logging

    def handshake(self):
        # create a version message
        version = VersionMessage()
        # send the version message
        self.send(version)
        # wait for peer's verack
        self.wait_for(VerAckMessage)

    def send(self, message):
        '''Send a message to the connected node'''
        # create a network envelope
        envelope = NetworkEnvelope(
            message.command, message.serialize())
        if self.logging:
            print('sending: {}'.format(envelope))
        # send the serialized envelope over the socket using sendall
        self.socket.sendall(envelope.serialize())

    def read(self):
        '''Read a message from the socket'''
        envelope = NetworkEnvelope.parse(self.stream)
        if self.logging:
            print('receiving: {}'.format(envelope))
        return envelope

    def wait_for(self, *message_classes):
        '''Wait for one of the messages in the list'''
        # initialize the command we have, which should be None
        command = None
        command_to_class = {m.command: m for m in message_classes}
        # loop until the command is in the commands we want
        while command not in command_to_class.keys():
            # get the next network message
            envelope = self.read()
            # set the command to be evaluated
            command = envelope.command
            # print(command)
            # we know how to respond to version and ping, handle that here
            if command == VersionMessage.command:
                # send verack
                self.send(VerAckMessage())
            elif command == PingMessage.command:
                # send pong
                self.send(PongMessage(envelope.payload))
        # return the envelope parsed as a member of the right message class
        return command_to_class[command].parse(envelope.stream())
