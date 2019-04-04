from io import BytesIO

from lib import handshake, read_msg, serialize_msg, read_varint, read_address


def read_addr_payload(stream):
    r = {}
    count = read_varint(stream)
    r['addresses'] = [read_address(stream) for _ in range(count)]
    return r


class Connection:

    def __init__(self, address):
        self.address = address
        self.sock = None
        self.peer_addresses = []
        self.listen = True

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

    def open(self):
        # TODO: get at the VERSION message
        self.sock = handshake(self.address)  # FIXME: save the version payload
        stream = self.sock.makefile('rb')

        # Request peer's peers
        self.sock.sendall(serialize_msg(b'getaddr'))

        while self.listen:
            msg = read_msg(stream)
            self.handle_msg(msg)

    def close(self):
        if self.sock:
            self.sock.close()
        
class Crawler:

    def __init__(self):
        self.addresses = []

    def prime(self):
        # TODO: ask DNS seeds for starter addresses
        self.addresses = [('92.109.124.73', 8333)]

    def crawl(self):
        print('Fetching initial addresses')
        self.prime()

        print('Entering main loop')
        while True:
            # Get next address from addresses and connect
            address = self.addresses.pop()

            try:
                # Establish connection
                print(f'Connecting to {address}')
                conn = Connection(address)
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
