import time
import socket

from io import BytesIO

from lib import handshake, read_msg, serialize_msg, read_varint, read_address, BitcoinProtocolError, serialize_version_payload, read_version_payload


def read_addr_payload(stream):
    r = {}
    count = read_varint(stream)
    r['addresses'] = [read_address(stream) for _ in range(count)]
    return r


class Node:

    def __init__(self, ip, port):
        self.ip = ip
        self.port = port

    @property
    def address(self):
        return (self.ip, self.port)


class Connection:

    def __init__(self, node, timeout=10):
        self.node = node
        self.timeout = timeout
        self.sock = None
        self.stream = None
        self.start = None

        # Results
        self.peer_version_payload = None
        self.nodes_discovered = []

    def send_version(self):
        payload = serialize_version_payload()
        msg = serialize_msg(command=b"version", payload=payload)
        self.sock.sendall(msg)

    def send_verack(self):
        msg = serialize_msg(command=b"verack")
        self.sock.sendall(msg)

    def send_pong(self, payload):
        res = serialize_msg(command=b'pong', payload=payload)
        self.sock.sendall(res)

    def send_getaddr(self):
        self.sock.sendall(serialize_msg(b'getaddr'))

    def handle_version(self, payload):
        # Save their version payload
        stream = BytesIO(payload)
        self.peer_version_payload = read_version_payload(stream)

        # Acknowledge
        self.send_verack()

    def handle_verack(self, payload):
        # Request peer's peers
        self.send_getaddr()

    def handle_ping(self, payload):
        self.send_pong(payload)

    def handle_addr(self, payload):
        payload = read_addr_payload(BytesIO(payload))
        if len(payload['addresses']) > 1:
            self.nodes_discovered = [
                Node(a['ip'], a['port']) for a in payload['addresses']
            ]

    def handle_msg(self):
        msg = read_msg(self.stream)
        command = msg['command'].decode()
        print(f'Received a "{command}"')
        method_name = f'handle_{command}'
        if hasattr(self, method_name):
            getattr(self, method_name)(msg['payload'])

    def remain_alive(self):
        timed_out = time.time() - self.start > self.timeout
        return not timed_out and not self.nodes_discovered

    def open(self):
        # Set start time
        self.start = time.time()

        # Open TCP connection
        print(f'Connecting to {self.node.ip}')
        self.sock = socket.create_connection(self.node.address, 
                                             timeout=self.timeout)
        self.stream = self.sock.makefile('rb')

        # Start version handshake
        self.send_version()

        # Handle messages until program exists
        while self.remain_alive():
            self.handle_msg()

    def close(self):
        # Clean up socket's file descriptor
        if self.sock:
            self.sock.close()


class Crawler:

    def __init__(self, nodes):
        self.nodes = nodes

    def crawl(self):
        while True:
            # Get next node and connect
            node = self.nodes.pop()

            try:
                conn = Connection(node)
                conn.open()
            except (OSError, BitcoinProtocolError) as e:
                print(f'Got error: {str(e)}')
            finally:
                conn.close()

            # Handle the results
            self.nodes.extend(conn.nodes_discovered)
            print(f'{conn.node.ip} reports version {conn.peer_version_payload}')


if __name__ == '__main__':
    nodes = [
        Node('92.109.124.73', 8333),
        Node('67.205.160.50', 8333),     
        Node('54.169.196.130', 8333),     
    ]

    Crawler(nodes).crawl()
