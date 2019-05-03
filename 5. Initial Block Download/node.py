from io import BytesIO

from network import PeerConnection, GetHeadersMessage, HeadersMessage, GetDataMessage, BlockMessage
from block import RAW_GENESIS_BLOCK, BlockHeader, Block


GENESIS_HEADER = BlockHeader.parse(BytesIO(RAW_GENESIS_BLOCK))
GENESIS_BLOCK = Block.parse(BytesIO(RAW_GENESIS_BLOCK))


class BitcoinNode:

    def __init__(self):
        self.headers = [GENESIS_HEADER]
        self.blocks = [GENESIS_BLOCK]
        self.peer = None

    def connect(self, host, port):
        self.peer = PeerConnection(host, port)
        self.peer.handshake()

    def receive_header(self, header):
        # append block headers received to headers array
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

    def receive_block(self, block):
        self.blocks.append(block)

    def request_blocks(self):
        # request 100 blocks
        next_height = len(self.blocks)
        headers = self.headers[next_height:next_height + 100]
        getdata = GetDataMessage()
        for header in headers:
            getdata.add_block(header.hash())
        self.peer.send(getdata)

        # wait for 10 blocks (FIXME)
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
