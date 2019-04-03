import time
import socket
import queue
import threading
import logging

from io import BytesIO

from lib import handshake, read_msg, serialize_msg, read_varint, read_address, serialize_version_payload, read_version_payload
import db_one as db

DNS_SEEDS = [
    'dnsseed.bitcoin.dashjr.org',
    'dnsseed.bluematt.me',
    'seed.bitcoin.sipa.be',
    'seed.bitcoinstats.com',
    'seed.bitcoin.sprovoost.nl',
]

logging.basicConfig(level="INFO", filename='crawler.log',
    format='%(threadName)-6s %(asctime)s %(message)s')
logger = logging.getLogger(__name__)

def read_addr_payload(stream):
    r = {}
    count = read_varint(stream)
    r['addresses'] = [read_address(stream) for _ in range(count)]
    return r


def fetch_addresses():
    addresses = []
    for dns_seed in DNS_SEEDS:
        try:
            addr_info = socket.getaddrinfo(dns_seed, 8333)
            new_addresses = [ai[-1][:2] for ai in addr_info]
            addresses.extend(list(set(new_addresses)))
        except:
            logging.info(f'Encountered error connecting to {dns_seed}')
    return addresses


class Connection:

    def __init__(self, address, timeout=20):
        self.address = address
        self.sock = None
        self.peer_addresses = []
        self.timeout = timeout
        self.handshake_start = None
        self.handshake_end = None
        self.version_payload = None

    def send_version(self):
        payload = serialize_version_payload()
        msg = serialize_msg(command=b"version", payload=payload)
        self.sock.sendall(msg)

    def send_verack(self):
        self.sock.sendall(serialize_msg(command=b"verack"))

    def send_pong(self, payload):
        res = serialize_msg(command=b'pong', payload=payload)
        self.sock.sendall(res)

    def send_getaddr(self):
        self.sock.sendall(serialize_msg(b'getaddr'))

    def handle_version(self, payload):
        # Save version payload
        stream = BytesIO(payload)
        version_payload = read_version_payload(stream)
        self.version_payload = version_payload

        # Next step in version handshake
        self.send_verack()

    def handle_verack(self, payload):
        # Mark the connection as complete
        self.handshake_end = time.time()

        # Request their addresses
        self.send_getaddr()

    def handle_ping(self, payload):
        self.send_pong(payload)

    def handle_pong(self, payload):
        res = serialize_msg(command=b'pong', payload=payload)
        self.sock.sendall(res)

    def handle_addr(self, payload):
        payload = read_addr_payload(BytesIO(payload))
        if len(payload['addresses']) > 1:
            # persist addresses and exit connection
            self.peer_addresses = [
                (a['ip'], a['port']) for a in payload['addresses']
            ]

    def handle_msg(self, msg):
        command = msg['command'].decode()
        logging.info(f'Received a "{command}" of {len(msg["payload"])} bytes')
        method = f'handle_{command}'  # handle_addr, handle_block, etc
        if hasattr(self, method):
            getattr(self, method)(msg['payload'])

    def remain_alive(self):
        awaiting_addr = len(self.peer_addresses) == 0
        elapsed = time.time() - self.handshake_start
        timed_out = elapsed > self.timeout
        return awaiting_addr and not timed_out

    def open(self):
        self.handshake_start = time.time()

        # TODO: get at the VERSION message
        self.sock = socket.create_connection(self.address, timeout=self.timeout)
        stream = self.sock.makefile('rb')

        # Initiate version handshake
        self.send_version()

        while self.remain_alive():
            msg = read_msg(stream)
            self.handle_msg(msg)

    def close(self):
        if self.sock:
            self.sock.close()


class Worker(threading.Thread):

    def __init__(self, inputs, outputs):
        threading.Thread.__init__(self)
        self.inputs = inputs
        self.outputs = outputs

    def run(self):
        logging.info('Starting')
        while True:
            # Get next address from addresses and connect
            address = self.inputs.get()

            try:
                # Establish connection
                logging.info(f'Connecting to {address}')
                conn = Connection(address, timeout=1)
                conn.open()
                logging.info(f'Received {len(conn.peer_addresses)} addresses from {address}')

            except Exception as e:
                logging.info(f'Got error: {str(e)}')
                continue
            
            finally:
                conn.close()
                self.outputs.put(conn)

class Crawler:

    def __init__(self, num_workers):
        self.worker_inputs = queue.Queue()
        self.worker_outputs = queue.Queue()
        self.workers = [Worker(self.worker_inputs, self.worker_outputs)
                        for _ in range(num_workers)]

    def prime(self):
        addresses = fetch_addresses()
        for address in addresses:
            self.worker_inputs.put(address)
        logging.info(f'Fetched {len(addresses)} addresses')

    def print_report(self):
        print(f'Found {db.count_nodes()} nodes so far')

    def main_loop(self):
        while True:
            # Get next result
            conn = self.worker_outputs.get()
            # Save to DB
            db.process_crawler_output(conn)
            # Prime worker_inputs
            for address in conn.peer_addresses:
                self.worker_inputs.put(address)
            # Print status report
            self.print_report()

    def crawl(self):
        # Fill the work queue
        self.prime()

        # Run the workers
        for worker in self.workers:
            worker.start()
        
        # Manage inputs and outputs
        self.main_loop()

if __name__ == '__main__':
    # Delete and recreate the database
    db.drop_and_create_tables()

    # Run the crawler
    Crawler(5).crawl()
