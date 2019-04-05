import time

from io import BytesIO

from lib import handshake, read_msg, serialize_msg, read_varint, read_address, BitcoinProtocolError


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

    def __init__(self, node):
        self.node = node
        self.sock = None
        self.stream = None
        self.start = None

        # Results
        self.peer_version_payload = None
        self.nodes_discovered = []

    def handle_msg(self):
        msg = read_msg(self.stream)
        command = msg['command']
        payload_len = len(msg['payload'])
        print(f'Received a "{command}" containing {payload_len} bytes')

        # Respond to "ping"
        if command == b'ping':
            res = serialize_msg(command=b'pong', payload=msg['payload'])
            self.sock.sendall(res)
            print("Send 'pong'")

        # Specially handle peer lists
        if command == b'addr':
            payload = read_addr_payload(BytesIO(msg['payload']))
            if len(payload['addresses']) > 1:
                self.nodes_discovered = [
                    Node(a['ip'], a['port']) for a in payload['addresses']
                ]

    def remain_alive(self):
        return not self.nodes_discovered

    def open(self):
        # Set start time
        self.start = time.time()

        # Open TCP connection
        print(f'Connecting to {self.node.ip}')
        self.sock = handshake(self.node.address)  # FIXME: save the version payload
        self.stream = self.sock.makefile('rb')

        # Request peer's peers
        self.sock.sendall(serialize_msg(b'getaddr'))

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
        pass

def crawler(nodes):
    while True:
        # Get next address from addresses and connect
        node = nodes.pop()

        try:
            conn = Connection(node)
            conn.open()
        except (OSError, BitcoinProtocolError) as e:
            print(f'Got error: {str(e)}')
            continue
        finally:
            conn.close()

        # Handle the results
        nodes.extend(conn.nodes_discovered)
        print(f'{conn.node.ip} report version {conn.peer_version_payload}')


if __name__ == '__main__':
    nodes = [
        Node('92.109.124.73', 8333),
        Node('67.205.160.50', 8333),     
        Node('54.169.196.130', 8333),     
    ]

    crawler(nodes)
