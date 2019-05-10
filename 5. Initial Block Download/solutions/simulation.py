import time
from unittest import TestCase
from io import BytesIO

from ecdsa import SigningKey, SECP256k1
from blockchain import Blockchain, ConsensusError
from tx import TxIn, Tx, TxOut
from script import Script, p2pk_script
from helper import little_endian_to_int, int_to_little_endian, merkle_root, target_to_bits, bits_to_target, hash256
from block import Block, FULL_GENESIS_BLOCK


genesis = Block.parse(BytesIO(FULL_GENESIS_BLOCK))

bits = target_to_bits(16**62)

def create_sk(secret):
    return SigningKey.from_secret_exponent(secret,
            curve=SECP256k1, hashfunc=lambda x: x)


def one_insufficient_proof():
    proof = b'1111111111111111111111111111111111111111111111111111111111111111'
    coinbase = Tx()


def tx_hashes(txns):
    return [tx.hash() for tx in txns]



def simulate():
    blockchain = Blockchain()


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


def missing_coinbase(blockchain):
    block = mine(Block(
        version=1,
        prev_block=blockchain.headers[-1].hash(),
        merkle_root=merkle_root([b'xyz']),
        timestamp=int(time.time()),
        bits=bits,
        nonce=b'\x00\x00\x00\x00',
        txns=[]
    ))
    return block

def missing_coinbase_hints():
    yield "Look block.txns"
    yield "Coinbase is missing"


def fail(chain, blk, hints_func):
    global blockchain
    global block
    global hints
    blockchain = chain
    block = blk
    hints = hints_func()


def simulation():
    blockchain = Blockchain()
    block = missing_coinbase(blockchain)
    try:
        blockchain.receive_block(block)
        print(f'Error: you accepted a bad block at height {len(blockchain.blocks)-1}')
        fail(blockchain, block, missing_coinbase_hints)
        return
    except ConsensusError as e:
        print(f'Block at height {len(blockchain.blocks)-1} correctly accepted')

    print('All tests pass!')

if __name__ == '__main__':
    simulation()


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
