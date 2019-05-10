import time
from os import urandom
from unittest import TestCase
from io import BytesIO

from ecdsa import SigningKey, SECP256k1
from blockchain import Blockchain
from tx import TxIn, Tx, TxOut
from script import Script, p2pk_script
from helper import little_endian_to_int, int_to_little_endian, merkle_root, target_to_bits, bits_to_target, hash256
from block import Block, FULL_GENESIS_BLOCK


genesis = Block.parse(BytesIO(FULL_GENESIS_BLOCK))
starting_bits = target_to_bits(16**62)


def create_sk(secret):
    return SigningKey.from_secret_exponent(secret,
            curve=SECP256k1, hashfunc=lambda x: x)


# some private keys
bob_sk = create_sk(100)
bob_vk = bob_sk.verifying_key
bob_sec = bob_vk.to_sec(compressed=False)

alice_sk = create_sk(100)
alice_vk = alice_sk.verifying_key
alice_sec = alice_vk.to_sec(compressed=False)


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

def mine(block):
    while not block.check_pow():
        block.nonce = int_to_little_endian(little_endian_to_int(block.nonce) + 1, 4)
    return block

def prepare_coinbase(sec):
    tx_in = TxIn(
        prev_tx=b'\x00'*32,
        prev_index=0xffffffff,
        script_sig=p2pk_script(urandom(10)),
    )
    tx_out = TxOut(
        amount=50*100_000_000,
        script_pubkey=p2pk_script(sec),
    )
    return Tx(
        version=1,
        tx_ins=[tx_in], 
        tx_outs=[tx_out],
        locktime=0,
    )


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


def wrong_bits(blockchain):
    block = mine(Block(
        version=1,
        prev_block=blockchain.headers[-1].hash(),
        merkle_root=merkle_root([b'xyz']),
        timestamp=int(time.time()),
        bits=target_to_bits(16**63),
        nonce=b'\x00\x00\x00\x00',
        txns=[prepare_coinbase(bob_sec)]
    ))
    valid = False
    hints = make_hints([
        f'Block.bits should be {repr(starting_bits)}',
    ])
    return block, valid, hints

def insufficient_proof(blockchain):
    block = Block(
        version=1,
        prev_block=blockchain.headers[-1].hash(),
        merkle_root=merkle_root([b'xyz']),  # FIXME
        timestamp=int(time.time()),
        bits=starting_bits,
        nonce=b'\x00\x00\x00\x00',
        txns=[prepare_coinbase(bob_sec)]
    )
    assert not block.check_pow()
    valid = False
    hints = make_hints([
        f'Proof-of-Work not satisfied',
    ])
    return block, valid, hints

def missing_coinbase(blockchain):
    block = mine(Block(
        version=1,
        prev_block=blockchain.headers[-1].hash(),
        merkle_root=merkle_root([b'xyz']),  # FIXME
        timestamp=int(time.time()),
        bits=starting_bits,
        nonce=b'\x00\x00\x00\x00',
        txns=[]
    ))
    valid = False
    hints = make_hints([
        "Look block.txns",
        "Coinbase is missing",
    ])
    return block, valid, hints


def bad_coinbase(blockchain):
    # this scenario sucks b/c we test multiple things and it's unclear whether the latter
    # checks are even happening
    tx_in = TxIn(
        prev_tx=b'\x00'*32,
        prev_index=0xffffffff,
        script_sig=p2pk_script(urandom(10)),
    )
    tx_out = TxOut(
        amount=100*100_000_000,
        script_pubkey=p2pk_script(bob_sec),
    )
    coinbase = Tx(
        version=1,
        tx_ins=[tx_in],
        tx_outs=[tx_out],
        locktime=0,
    )
    block = mine(Block(
        version=1,
        prev_block=blockchain.headers[-1].hash(),
        merkle_root=merkle_root([coinbase.hash()]),  # FIXME
        timestamp=int(time.time()),
        bits=starting_bits,
        nonce=b'\x00\x00\x00\x00',
        txns=[coinbase]
    ))
    valid = False
    hints = make_hints([
        "Bad coinbase",
    ])
    return block, valid, hints


def good_coinbase(blockchain):
    coinbase = prepare_coinbase(bob_sec)
    block = mine(Block(
        version=1,
        prev_block=blockchain.headers[-1].hash(),
        merkle_root=merkle_root([coinbase.hash()]),  # FIXME
        timestamp=int(time.time()),
        bits=starting_bits,
        nonce=b'\x00\x00\x00\x00',
        txns=[coinbase]
    ))
    valid = True
    hints = make_hints([
        'We need to update the utxo set'
    ])
    # FIXME: check that utxo_set was updated
    return block, valid, hints



def simulate():
    scenarios = [
        wrong_bits,
        insufficient_proof,
        missing_coinbase,
        bad_coinbase,
        good_coinbase,
    ]
    blockchain = Blockchain()
    for scenario in scenarios:
        block, valid, hints = scenario(blockchain)
        accepted = blockchain.receive_block(block)
        num_blocks = len(blockchain.blocks)
        # FIXME: would be nice if the reasons for rejection showed up here
        if valid and accepted:
            print(f'Pass: accepted valid block at height {num_blocks-1}')
        elif valid and not accepted:
            print(f'Fail: rejected valid block at height {num_blocks}')
            return fail(blockchain, block, hints)
        elif not valid and accepted:
            print(f'Fail: accepted invalid block at height {num_blocks-1}')
            return fail(blockchain, block, hints)
        elif not valid and not accepted:
            print(f'Pass: rejected invalid block at height {num_blocks}')
    print('All tests passed!')


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
            bits=starting_bits,
            nonce=b'\x00\x00\x00\x00',
            txns=[coinbase]
        ))
        assert Block.parse(BytesIO(block.serialize())).hash() == block.hash()
