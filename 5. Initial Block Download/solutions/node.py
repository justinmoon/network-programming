from io import BytesIO

from solutions.network import PeerConnection, GetHeadersMessage, HeadersMessage, GetDataMessage, BlockMessage
from solutions.block import RAW_GENESIS_BLOCK, BlockHeader, Block
from lib import target_to_bits


GENESIS_HEADER = BlockHeader.parse(BytesIO(RAW_GENESIS_BLOCK))
GENESIS_BLOCK = Block.parse(BytesIO(RAW_GENESIS_BLOCK))


starting_bits = target_to_bits(16**62)


class BitcoinNode:

    def __init__(self):
        self.headers = [GENESIS_HEADER]
        self.blocks = [GENESIS_BLOCK]
        self.utxo_set = {}
        self.peer = None

    def connect(self, host, port):
        self.peer = PeerConnection(host, port)
        self.peer.handshake()

    def receive_header(self, header):
        # TODO: verify hash matches
        # TODO: check proof-of-work
        # append block headers received to headers array
        previous = self.headers[-1]
        if header.prev_block != previous.hash():
            raise RuntimeError('discontinuous block at {}'.format(len(self.headers)))
        self.headers.append(header)

    def request_headers(self):
        # get "getheaders" message
        start_block = self.headers[-1].hash()
        getheaders = GetHeadersMessage(start_block=start_block)
        self.peer.send(getheaders)

        # wait for the "headers" response
        headers_msg = self.peer.wait_for(HeadersMessage)
        for header in headers_msg.headers:
            self.receive_header(header)
        print(f'we now have {len(self.headers)} headers')

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

    def request_blocks(self):
        # request 100 blocks
        next_height = len(self.blocks)
        headers = self.headers[next_height:next_height + 100]
        getdata = GetDataMessage()
        for header in headers:
            getdata.add_block(header.hash())
        self.peer.send(getdata)

        # wait for 100 blocks (FIXME)
        for _ in range(100):
            block_message = self.peer.wait_for(BlockMessage)
            self.receive_block(block_message.block)
        print(f'we now have {len(self.blocks)} blocks')

    def sync(self, max_blocks):
        while len(self.headers) < max_blocks:
            self.request_headers()
        while len(self.blocks) < len(self.headers):
            self.request_blocks()


if __name__ == '__main__':
    bitcoin_node = BitcoinNode()
    bitcoin_node.connect('72.50.221.9', 8333)
    bitcoin_node.sync(1000)
