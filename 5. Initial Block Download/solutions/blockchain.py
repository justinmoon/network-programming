from io import BytesIO
from network import SimpleNode, GetHeadersMessage, HeadersMessage, GetDataMessage, InvMessage, BlockMessage, InventoryItem
from block import BlockHeader, Block, GENESIS_BLOCK
from helper import int_to_little_endian, little_endian_to_int, encode_varint, read_varint, target_to_bits

genesis_parsed = BlockHeader.parse(BytesIO(GENESIS_BLOCK))
SIGHASH_ALL = 1


starting_bits = target_to_bits(16**62)  # FIXME should we pass to Blockchin class?

class Blockchain:

    def __init__(self):
        # (txid, index) -> ???
        self.headers = [genesis_parsed]
        self.blocks = [genesis_parsed]  # think this is unspendable ???
        self.utxo_set = {}
        self.node = SimpleNode('mainnet.programmingbitcoin.com', testnet=False)

    def validate_header(self, header):
        previous = self.headers[-1]
        if header.prev_block != previous.hash():
            raise RuntimeError('discontinuous block at {}'.format(len(self.headers)))
        # TODO: check bits

    def receive_header(self, header):
        self.validate_header(header)
        self.headers.append(header)

    def download_headers(self):
        self.node.handshake()
        genesis_parsed = BlockHeader.parse(BytesIO(GENESIS_BLOCK))
        while len(self.headers) < 10000:
            start_block = self.headers[-1].hash()
            getheaders = GetHeadersMessage(start_block=start_block)
            self.node.send(getheaders)
            headers = self.node.wait_for(HeadersMessage)
            for header in headers.blocks:
                self.receive_header(header)

    def request_blocks(self, headers):
        getdata_message = GetDataMessage()
        for header in headers:
            getdata_message.add_data(2, header.hash())
        self.node.send(getdata_message)

    def validate_block(self, block):
        if block.bits != starting_bits:
            print('bad bits')
            return False
        if not block.check_pow():
            print('bad pow')
            return False
        if not len(block.txns):
            print('missing coinbase')
            return False
        if not block.txns[0].is_valid_coinbase():
            print('bad coinbase')
            return False
        for tx in block.txns[1:]:
            if not tx.verify(self.utxo_set):
                print('invalid transaction')
                return False
        return True

    def update_utxo_set(self, block):
        for tx in block.txns:
            for index, tx_out in enumerate(tx.tx_outs):
                outpoint = (tx.id(), index)
                self.utxo_set[outpoint] = tx_out

    def receive_block(self, block):
        if not self.validate_block(block):
            return False
        else:
            self.update_utxo_set(block)
            self.blocks.append(block)
            return True

    def download_blocks(self):
        while len(self.blocks) < len(self.headers):
            # request 10 blocks
            start_index = len(self.blocks)
            headers = self.headers[start_index:start_index + 10]
            self.request_blocks(headers)
            # wait for 10 blocks (FIXME)
            for _ in range(10):
                block_message = self.node.wait_for(BlockMessage)
                self.receive_block(block_message.block)
            print(f'we now have {len(self.blocks)} blocks')

    def run(self):
        self.download_headers()
        self.download_blocks()


if __name__ == '__main__':
    blockchain = Blockchain()
    blockchain.run()
