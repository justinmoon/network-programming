import time
import socket

from io import BytesIO

from lib import handshake, read_msg, serialize_msg, read_varint, read_address

DNS_SEEDS = [
    'dnsseed.bitcoin.dashjr.org',
    'dnsseed.bluematt.me',
    'seed.bitcoin.sipa.be',
    'seed.bitcoinstats.com',
    'seed.bitcoin.sprovoost.nl',
]


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
            print(f'Encountered error connecting to {dns_seed}')
    return addresses


class Connection:

    def __init__(self, address, timeout=20):
        self.address = address
        self.sock = None
        self.peer_addresses = []
        self.timeout = timeout
        self.start_time = None

    def handle_ping(self, payload):
        res = serialize_msg(command=b'pong', payload=payload)
        self.sock.sendall(res)

    def handle_addr(self, payload):
        payload = read_addr_payload(BytesIO(payload))
        if len(payload['addresses']) > 1:
            # persist addresses and exit connection
            self.peer_addresses = [
                (a['ip'], a['port']) for a in payload['addresses']
            ]
            self.listen = False

    def handle_msg(self, msg):
        command = msg['command'].decode()
        print(f'Received a "{command}" of {len(msg["payload"])} bytes')
        method = f'handle_{command}'  # handle_addr, handle_block, etc
        if hasattr(self, method):
            getattr(self, method)(msg['payload'])

    def remain_alive(self):
        awaiting_addr = len(self.peer_addresses) == 0
        elapsed = time.time() - self.start_time
        timed_out = elapsed > self.timeout
        return awaiting_addr and not timed_out
        
    def open(self):
        self.start_time = time.time()

        # TODO: get at the VERSION message
        self.sock = handshake(self.address)  # FIXME: save the version payload
        stream = self.sock.makefile('rb')

        # Request peer's peers
        self.sock.sendall(serialize_msg(b'getaddr'))

        while self.remain_alive():
            msg = read_msg(stream)
            self.handle_msg(msg)

    def close(self):
        if self.sock:
            self.sock.close()
        
class Crawler:

    def __init__(self):
        self.addresses = []

    def prime(self):
        self.addresses = fetch_addresses()

    def crawl(self):
        print('Fetching initial addresses')
        self.prime()
        print(f'Fetched {len(self.addresses)}')

        print('Entering main loop')
        while True:
            # Get next address from addresses and connect
            address = self.addresses.pop()

            try:
                # Establish connection
                print(f'Connecting to {address}')
                conn = Connection(address, timeout=1)
                conn.open()
                print(f'Received {len(conn.peer_addresses)} addresses from {address}')

            except Exception as e:
                print(f'Got error: {str(e)}')
                continue
            
            finally:
                conn.close()

            self.addresses.extend(conn.peer_addresses)


if __name__ == '__main__':
    Crawler().crawl()
