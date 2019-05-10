import time
from unittest import TestCase
from io import BytesIO

from ecdsa import SigningKey, SECP256k1
from blockchain import Blockchain
from tx import TxIn, Tx, TxOut
from script import Script, p2pk_script
from helper import little_endian_to_int, int_to_little_endian, merkle_root, target_to_bits, bits_to_target, hash256
from block import Block, FULL_GENESIS_BLOCK


genesis = Block.parse(BytesIO(FULL_GENESIS_BLOCK))
staring_bits = target_to_bits(16**62)


def create_sk(secret):
    return SigningKey.from_secret_exponent(secret,
            curve=SECP256k1, hashfunc=lambda x: x)


def tx_hashes(txns):
    return [tx.hash() for tx in txns]


def mine(block):
    target = bits_to_target(block.bits)
    nonce = 0
    serialized_block = block.serialize()
    nonce_index = 76
    while True:
        ser = serialized_block[:76] + int_to_little_endian(nonce, 4) + serialized_block[80:]
        proof = little_endian_to_int(hash256(ser))
        if proof < target:
            block.nonce = int_to_little_endian(nonce, 4)
            return block
        else:
            nonce += 1


def make_hints(hints):
    for hint in hints:
        yield hint
    while True:
        yield 'No more hints'


def fail(chain, blk, _hints):
    global blockchain
    global block
    global hints
    blockchain = chain
    block = blk
    hints = _hints


def missing_coinbase(blockchain):
    block = mine(Block(
        version=1,
        prev_block=blockchain.headers[-1].hash(),
        merkle_root=merkle_root([b'xyz']),
        timestamp=int(time.time()),
        bits=staring_bits,
        nonce=b'\x00\x00\x00\x00',
        txns=[]
    ))
    valid = False
    hints = make_hints([
        "Look block.txns",
        "Coinbase is missing",
    ])
    return block, valid, hints


def simulate():
    scenarios = [
        missing_coinbase,
    ]
    blockchain = Blockchain()
    for scenario in scenarios:
        block, valid, hints = missing_coinbase(blockchain)
        accepted = blockchain.receive_block(block)
        height = len(blockchain.blocks) - 1
        if valid and accepted:
            print(f'Pass: accepted valid block at height {height}')
        elif valid and not accepted:
            print(f'Fail: rejected valid block at height {height}')
            return fail(blockchain, block, hints)
        elif not valid and accepted:
            print(f'Fail: accepted invalid block at height {height}')
            return fail(blockchain, block, hints)
        elif not valid and not accepted:
            print(f'Pass: rejected invalid block at height {height}')


if __name__ == '__main__':
    simulate()


class RandomTests(TestCase):

    def test_block_parsing_and_serialization(self):
        tx_in = TxIn(
            prev_tx=b'\x00'*32,
            prev_index=0xffffffff,
            script_sig=Script([b'muhhh coinz']),
        )
        sk = create_sk(100)
        sec = sk.verifying_key.to_sec(compressed=False)
        tx_out = TxOut(
            amount=50*100_000_000,
            script_pubkey=p2pk_script(sec),
        )
        coinbase = Tx(
            version=1,
            tx_ins=[tx_in], 
            tx_outs=[tx_out],
            locktime=0,
        )
        block = mine(Block(
            version=1,
            prev_block=genesis.hash(),
            merkle_root=merkle_root([coinbase.hash()]),
            timestamp=int(time.time()),
            bits=bits,
            nonce=b'\x00\x00\x00\x00',
            txns=[coinbase]
        ))
        assert Block.parse(BytesIO(block.serialize())).hash() == block.hash()
