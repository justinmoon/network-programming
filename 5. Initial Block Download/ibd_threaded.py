# TODO: request new peers from connected peer

import threading

from network import *
from block import *

genesis_parsed = BlockHeader.parse(BytesIO(GENESIS_BLOCK))


class Blockchain:
    
    def __init__(self):
        self.headers = [genesis_parsed]
        self.blocks = [genesis_parsed] + [None] * 10000
        self.node = SimpleNode('mainnet.programmingbitcoin.com', testnet=False)
        self.lock = threading.Lock()
        
    def receive_header(self, header):
        if self.headers[-1].hash() != header.prev_block:
            msg = 'discontinuous block at {}'.format(len(self.headers))
            raise RuntimeError(msg)
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

    def request_blocks(self, headers, node=None):
        if not node:
            node = self.node
        getdata_message = GetDataMessage()
        for header in headers:
            getdata_message.add_data(2, header.hash())
        node.send(getdata_message)

    def receive_block(self, block):
        # how to find the index of this block?
        height = -1
        for index, header in enumerate(self.headers):
            if header.hash() == block.hash():
                height = index
        if height < 0:
            raise RuntimeError()
        self.blocks[height] = block

            
def download_blocks(host, blockchain, start_index, end_index, step):
    print(f'({host}) starting')
    node = SimpleNode(host, testnet=False)
    node.handshake()
    current = start_index
    while start_index < end_index:
        # request 10 blocks
        headers = blockchain.headers[start_index:start_index + step]
        start_index += step
        blockchain.request_blocks(headers, node)
        # wait for 10 blocks (FIXME)
        for _ in range(10):
            block_message = node.wait_for(BlockMessage)
            with blockchain.lock:
                blockchain.receive_block(block_message.block)
        num_blocks = len([block for block in blockchain.blocks if block is not None])
        print(f'({host}) we now have {num_blocks} blocks')
            
blockchain = Blockchain()
blockchain.download_headers()


stop_threads = False
thread1 = threading.Thread(
    target=download_blocks,
    args=('92.62.34.184', blockchain, 1, 201, 10)
)
thread1.start()

thread2 = threading.Thread(
    target=download_blocks,
    args=('212.9.185.194', blockchain, 200, 401, 10)
)
thread2.start()

thread1.join()
thread2.join()

print('finished')
non_empty_blocks = len([block for block in blockchain.blocks
                        if block is not None])
print(non_empty_blocks)     

for i in range(400):
    assert blockchain.headers[i].hash() == blockchain.blocks[i].hash()

print('blockchain is all good!')
