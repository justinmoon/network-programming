from io import BytesIO

from lib import handshake, read_msg, serialize_msg, read_varint, read_address


def read_addr_payload(stream):
    r = {}
    count = read_varint(stream)
    r['addresses'] = [read_address(stream) for _ in range(count)]
    return r


def crawler(addresses):
    while True:
        # Get next address from addresses and connect
        address = addresses.pop()

        try:
            # Establish connection
            print(f'Connecting to {address}')
            sock = handshake(address)  # FIXME: save the version payload
            stream = sock.makefile('rb')

            # Request peer's peers
            sock.sendall(serialize_msg(b'getaddr'))

            # Print every gossip message we receive
            while True:
                msg = read_msg(stream)
                command = msg['command']
                payload_len = len(msg['payload'])
                print(f'Received a "{command}" containing {payload_len} bytes')

                # Respond to "ping"
                if command == b'ping':
                    res = serialize_msg(command=b'pong', payload=msg['payload'])
                    sock.sendall(res)
                    print("Send 'pong'")

                # Specially handle peer lists
                if command == b'addr':
                    payload = read_addr_payload(BytesIO(msg['payload']))
                    if len(payload['addresses']) > 1:
                        addresses.extend([
                            (a['ip'], a['port']) for a in payload['addresses']
                        ])
                        break
        except Exception as e:
            print(f'Got error: {str(e)}')
            continue


if __name__ == '__main__':
    remote_addr = [('92.109.124.73', 8333)]

    # local_addr = 'localhost', 8333

    crawler(remote_addr)
