from io import BytesIO
from unittest import TestCase

from lib import little_endian_to_int, int_to_little_endian, double_sha256, read_varint, bits_to_target
from tx import Tx


RAW_GENESIS_BLOCK = bytes.fromhex('0100000000000000000000000000000000000000000000000000000000000000000000003ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a29ab5f49ffff001d1dac2b7c0101000000010000000000000000000000000000000000000000000000000000000000000000ffffffff4d04ffff001d0104455468652054696d65732030332f4a616e2f32303039204368616e63656c6c6f72206f6e206272696e6b206f66207365636f6e64206261696c6f757420666f722062616e6b73ffffffff0100f2052a01000000434104678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5fac00000000')


class BlockHeader:

    def __init__(self, version, prev_block, merkle_root,
                 timestamp, bits, nonce):
        self.version = version
        self.prev_block = prev_block
        self.merkle_root = merkle_root
        self.timestamp = timestamp
        self.bits = bits
        self.nonce = nonce

    @classmethod
    def parse(cls, s):
        '''Takes a byte stream and parses a block. Returns a Block object'''
        # s.read(n) will read n bytes from the stream
        # version - 4 bytes, little endian, interpret as int
        # prev_block - 32 bytes, little endian (use [::-1] to reverse)
        # merkle_root - 32 bytes, little endian (use [::-1] to reverse)
        # timestamp - 4 bytes, little endian, interpret as int
        # bits - 4 bytes
        # nonce - 4 bytes
        # initialize class
        raise NotImplementedError()

    def serialize(self):
        '''Returns the 80 byte block header'''
        # version - 4 bytes, little endian
        # prev_block - 32 bytes, little endian
        # merkle_root - 32 bytes, little endian
        # timestamp - 4 bytes, little endian
        # bits - 4 bytes
        # nonce - 4 bytes
        raise NotImplementedError()

    def hash(self):
        '''Returns the double_sha256 interpreted little endian of the block'''
        # serialize
        # double_sha256
        # reverse
        raise NotImplementedError()

    def id(self):
        raise NotImplementedError()

    def check_pow(self):
        '''Returns whether this block satisfies proof of work'''
        # get the double_sha256 of the serialization of this block
        # interpret this hash as a little-endian number
        # return whether this integer is less than the target
        raise NotImplementedError()


class BlockHeaderTest(TestCase):

    def test_parse(self):
        block_raw = bytes.fromhex('020000208ec39428b17323fa0ddec8e887b4a7c53b8c0a0a220cfd0000000000000000005b0750fce0a889502d40508d39576821155e9c9e3f5c3157f961db38fd8b25be1e77a759e93c0118a4ffd71d')
        stream = BytesIO(block_raw)
        block = BlockHeader.parse(stream)
        self.assertEqual(block.version, 0x20000002)
        want = bytes.fromhex('000000000000000000fd0c220a0a8c3bc5a7b487e8c8de0dfa2373b12894c38e')
        self.assertEqual(block.prev_block, want)
        want = bytes.fromhex('be258bfd38db61f957315c3f9e9c5e15216857398d50402d5089a8e0fc50075b')
        self.assertEqual(block.merkle_root, want)
        self.assertEqual(block.timestamp, 0x59a7771e)
        self.assertEqual(block.bits, bytes.fromhex('e93c0118'))
        self.assertEqual(block.nonce, bytes.fromhex('a4ffd71d'))

    def test_serialize(self):
        block_raw = bytes.fromhex('020000208ec39428b17323fa0ddec8e887b4a7c53b8c0a0a220cfd0000000000000000005b0750fce0a889502d40508d39576821155e9c9e3f5c3157f961db38fd8b25be1e77a759e93c0118a4ffd71d')
        stream = BytesIO(block_raw)
        block = BlockHeader.parse(stream)
        self.assertEqual(block.serialize(), block_raw)

    def test_hash(self):
        block_raw = bytes.fromhex('020000208ec39428b17323fa0ddec8e887b4a7c53b8c0a0a220cfd0000000000000000005b0750fce0a889502d40508d39576821155e9c9e3f5c3157f961db38fd8b25be1e77a759e93c0118a4ffd71d')
        stream = BytesIO(block_raw)
        block = BlockHeader.parse(stream)
        self.assertEqual(block.hash(), bytes.fromhex('0000000000000000007e9e4c586439b0cdbe13b1370bdd9435d76a644d047523'))

    def test_id(self):
        block_raw = bytes.fromhex('020000208ec39428b17323fa0ddec8e887b4a7c53b8c0a0a220cfd0000000000000000005b0750fce0a889502d40508d39576821155e9c9e3f5c3157f961db38fd8b25be1e77a759e93c0118a4ffd71d')
        stream = BytesIO(block_raw)
        block = BlockHeader.parse(stream)
        self.assertEqual(block.id(), '0000000000000000007e9e4c586439b0cdbe13b1370bdd9435d76a644d047523')

    def test_check_pow(self):
        block_raw = bytes.fromhex('04000000fbedbbf0cfdaf278c094f187f2eb987c86a199da22bbb20400000000000000007b7697b29129648fa08b4bcd13c9d5e60abb973a1efac9c8d573c71c807c56c3d6213557faa80518c3737ec1')
        stream = BytesIO(block_raw)
        block = BlockHeader.parse(stream)
        self.assertTrue(block.check_pow())
        block_raw = bytes.fromhex('04000000fbedbbf0cfdaf278c094f187f2eb987c86a199da22bbb20400000000000000007b7697b29129648fa08b4bcd13c9d5e60abb973a1efac9c8d573c71c807c56c3d6213557faa80518c3737ec0')
        stream = BytesIO(block_raw)
        block = BlockHeader.parse(stream)
        self.assertFalse(block.check_pow())


class Block(BlockHeader):

    def __init__(self, version, prev_block, merkle_root,
                 timestamp, bits, nonce, txns):
        BlockHeader.__init__(self, version, prev_block, merkle_root,
                timestamp, bits, nonce)
        self.txns = txns

    @classmethod
    def parse(cls, s):
        raise NotImplementedError()


class BlockTest(TestCase):

    def test_parse(self):
        raw_block = bytes.fromhex('010000006fe28c0ab6f1b372c1a6a246ae63f74f931e8365e15a089c68d6190000000000982051fd1e4ba744bbbe680e1fee14677ba1a3c3540bf7b1cdb606e857233e0e61bc6649ffff001d01e362990101000000010000000000000000000000000000000000000000000000000000000000000000ffffffff0704ffff001d0104ffffffff0100f2052a0100000043410496b538e853519c726a2c91e61ec11600ae1390813a627c66fb8be7947be63c52da7589379515d4e0a604f8141781e62294721166bf621e73a82cbf2342c858eeac00000000')
        block = Block.parse(BytesIO(raw_block))
        self.assertEqual(len(block.txns), 1)
