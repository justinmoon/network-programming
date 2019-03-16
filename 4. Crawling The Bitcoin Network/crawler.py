import socket
import time
import hashlib
import socks
import logging
import random

from io import BytesIO
from random import randint
from base64 import b32decode, b32encode
from queue import Queue
from threading import Thread, Lock

from db import observe_node, observe_error, create_tables, count_observations


logging.basicConfig(level="INFO", filename='crawler.log', 
        format='%(threadName)-6s %(asctime)s %(message)s')
logger = logging.getLogger(__name__)
NETWORK_MAGIC = b'\xf9\xbe\xb4\xd9'

visited_addresses_lock = Lock()
visited_addresses = set()

# docs say it should be this but p2p network seems end b"\x00" x2
# IPV4_PREFIX = b"\x00" * 10 + b"\xff" * 2
IPV4_PREFIX = b"\x00" * 10 + b"\x00" * 2
ONION_PREFIX = b"\xFD\x87\xD8\x7E\xEB\x43"  # ipv6 prefix for .onion address


def little_endian_to_int(b):
    return int.from_bytes(b, 'little')


def int_to_little_endian(n, length):
    return n.to_bytes(length, 'little')


def big_endian_to_int(b):
    return int.from_bytes(b, 'big')


def int_to_big_endian(n, length):
    return n.to_bytes(length, 'big')


def double_sha256(s):
    return hashlib.sha256(hashlib.sha256(s).digest()).digest()


def bytes_to_ip(b):
    if b[:6] == ONION_PREFIX:
        return b32encode(b[6:]).lower().decode("ascii") + ".onion"
    elif b[0:12] == IPV4_PREFIX:  # IPv4
        return socket.inet_ntop(socket.AF_INET, b[12:16])
    else:  # IPv6
        return socket.inet_ntop(socket.AF_INET6, b)


def ip_to_bytes(ip):
    if ip.endswith(".onion"):
        return ONION_PREFIX + b32decode(ip[:-6], True)
    elif ":" in ip:
        return socket.inet_pton(socket.AF_INET6, ip)
    else:
        return IPV4_PREFIX + socket.inet_pton(socket.AF_INET, ip)


def read_varint(s):
    '''read_varint reads a variable integer from a stream'''
    i = s.read(1)[0]
    if i == 0xfd:
        # 0xfd means the next two bytes are the number
        return little_endian_to_int(s.read(2))
    elif i == 0xfe:
        # 0xfe means the next four bytes are the number
        return little_endian_to_int(s.read(4))
    elif i == 0xff:
        # 0xff means the next eight bytes are the number
        return little_endian_to_int(s.read(8))
    else:
        # anything else is just the integer
        return i


def encode_varint(i):
    '''encodes an integer as a varint'''
    if i < 0xfd:
        return bytes([i])
    elif i < 0x10000:
        return b'\xfd' + int_to_little_endian(i, 2)
    elif i < 0x100000000:
        return b'\xfe' + int_to_little_endian(i, 4)
    elif i < 0x10000000000000000:
        return b'\xff' + int_to_little_endian(i, 8)
    else:
        raise RuntimeError('integer too large: {}'.format(i))


def read_version_payload(stream):
    r = {}
    r["version"] = little_endian_to_int(stream.read(4))
    r["services"] = little_endian_to_int(stream.read(8))
    r["timestamp"] = little_endian_to_int(stream.read(8))
    r["receiver_services"] = little_endian_to_int(stream.read(8))
    r["receiver_ip"] = bytes_to_ip(stream.read(16))
    r["receiver_port"] = big_endian_to_int(stream.read(2))
    r["sender_services"] = little_endian_to_int(stream.read(8))
    r["sender_ip"] = bytes_to_ip(stream.read(16))
    r["sender_port"] = big_endian_to_int(stream.read(2))
    r["nonce"] = little_endian_to_int(stream.read(8))
    r["user_agent"] = stream.read(read_varint(stream))
    r["latest_block"] = little_endian_to_int(stream.read(4))
    r["relay"] = little_endian_to_int(stream.read(1))
    return r


def serialize_version_payload(
        version=70015, services=0, timestamp=None,
        receiver_services=0,
        receiver_ip='0.0.0.0', receiver_port=8333,
        sender_services=0,
        sender_ip='0.0.0.0', sender_port=8333,
        nonce=None, user_agent=b'/advancing-bitcoin/',
        latest_block=0, relay=True):
    if timestamp is None:
        timestamp = int(time.time())
    if nonce is None:
        nonce = randint(0, 2**64)
    result = int_to_little_endian(version, 4)
    result += int_to_little_endian(services, 8)
    result += int_to_little_endian(timestamp, 8)
    result += int_to_little_endian(receiver_services, 8)
    result += ip_to_bytes(receiver_ip)
    result += int_to_big_endian(receiver_port, 2)
    result += int_to_little_endian(sender_services, 8)
    result += ip_to_bytes(sender_ip)
    result += int_to_little_endian(sender_port, 2)
    result += int_to_little_endian(nonce, 8)
    result += encode_varint(len(user_agent))
    result += user_agent
    result += int_to_little_endian(latest_block, 4)
    result += int_to_little_endian(int(relay), 1)
    return result


def read_address(stream):
    r = {}
    r["time"] = little_endian_to_int(stream.read(4))
    r["services"] = stream.read(8)
    r["ip"] = bytes_to_ip(stream.read(16))
    r["port"] = big_endian_to_int(stream.read(2))
    return r


def read_addr_payload(stream):
    r = {}
    count = read_varint(stream)
    r["addresses"] = [read_address(stream) for _ in range(count)]
    return r


def read_msg(stream):
    magic = stream.read(4)
    if magic != NETWORK_MAGIC:
        raise Exception(f'Magic is wrong: {magic}')
    command = stream.read(12)
    command = command.strip(b'\x00')
    payload_length = int.from_bytes(stream.read(4), 'little')
    checksum = stream.read(4)
    payload = stream.read(payload_length)
    calculated_checksum = double_sha256(payload)[:4]
    if calculated_checksum != checksum:
        raise Exception('Checksum does not match')
    return {
        "command": command,
        "payload": payload,
    }


def serialize_msg(command, payload):
    result = NETWORK_MAGIC
    result += command + b'\x00' * (12 - len(command))
    result += int_to_little_endian(len(payload), 4)
    result += double_sha256(payload)[:4]
    result += payload
    return result


def make_socket(address):
    if "onion" not in address[0]:
        r = socket.getaddrinfo(address[0], address[1], 0, 0, socket.SOL_TCP)
        sock = socket.socket(r[0][0], r[0][1], r[0][2])
    else:
        logger.info("Connecting over tor")
        proxy = ("127.0.0.1", 9050)
        timeout = 10
        socks.setdefaultproxy(socks.PROXY_TYPE_SOCKS5, proxy[0], proxy[1])
        sock = socks.socksocket()
        sock.settimeout(timeout)
    return sock


def connect(address):
    if "onion" not in address[0]:
        ai = socket.getaddrinfo(address[0], address[1], 0, 0, socket.SOL_TCP)
        tcp_listing = ai[0]
        socket_info, connect_info = tcp_listing[:-2], tcp_listing[-1]
        sock = socket.socket(*socket_info)
        sock.connect(connect_info)
    else:
        proxy = ("127.0.0.1", 9050)
        timeout = 10
        socks.setdefaultproxy(socks.PROXY_TYPE_SOCKS5, proxy[0], proxy[1])
        sock = socks.socksocket()
        sock.settimeout(timeout)
        sock.connect(address)
    return sock


def handshake(address):
    sock = socket.create_connection(address, timeout=20)
    stream = sock.makefile("rb")

    # Step 1: our version message
    payload = serialize_version_payload()
    msg = serialize_msg(b"version", payload)
    sock.sendall(msg)

    # Step 2: their version message
    msg = read_msg(stream)
    version_payload = read_version_payload(BytesIO(msg["payload"]))

    # Step 3: their version message
    msg = read_msg(stream)

    # Step 4: our verack
    msg = serialize_msg(b"verack", b"")
    sock.sendall(msg)

    return sock, version_payload


dns_seeds = [
    'dnsseed.bitcoin.dashjr.org',
    'dnsseed.bluematt.me',
    'seed.bitcoin.sipa.be',
    'seed.bitcoinstats.com',
    'seed.bitcoin.sprovoost.nl',
    'seed.bitnodes.io',
]


def fetch_ips(dns_seed):
    ip_list = []
    ais = socket.getaddrinfo(dns_seed, 0, 0, 0, 0)
    for result in ais:
        ip_list.append(result[-1][0])
    return list(set(ip_list))


def fetch_addresses():
    result = []
    for dns_seed in dns_seeds:
        try:
            ips = fetch_ips(dns_seed)
            addresses = [(ip, 8333) for ip in ips]
            result.extend(addresses)
        except:
            logger.info(f"Error fetching addresses from {dns_seed}")
            continue
    return result


def next_address(q, visited_addresses):
    while True:
        address = q.get()
        if address not in visited_addresses:
            with visited_addresses_lock:
                visited_addresses.add(address)
            return address


def worker(worker_id, address_queue, run_for):
    time.sleep(random.random()*5)  # space them out a bit
    logger.info(f"Starting worker #{worker_id}")
    outer_start = time.time()
    while time.time() - outer_start < run_for:  # FIXME: Can't run indefinitely for now

        logger.info(f'Q contains {address_queue.qsize()}')
        address = next_address(address_queue, visited_addresses)
        logger.info(f'Connecting to {address}')

        # If we can't connect, proceed to next addressf
        try:
            sock, version_payload = handshake(address)
        except Exception as e:
            observe_error(address, str(e))
            continue

        stream = sock.makefile("rb")

        # Save the address & version payload
        observe_node(address, version_payload)

        # Request their peer list
        # FIXME hacky excetion handling
        try:
            sock.send(serialize_msg(b"getaddr", b""))
        except Exception as e:
            observe_error(address, str(e))
            break
        logger.info('Sent "getaddr". Awaiting "addr" response.')

        # Only wait `TIMEOUT` seconds for addr message
        start = time.time()
        while True:
            if time.time() - start > 30:
                logger.info('Never received "getaddr"')
                break

            # If connection breaks, proceed to next address
            try:
                msg = read_msg(stream)
            except Exception as e:
                observe_error(address, str(e))
                break

            # Only handle "addr" messages
            if msg["command"] == b"addr":
                addr_payload = read_addr_payload(BytesIO(msg["payload"]))
                if len(addr_payload["addresses"]) > 60:
                    for address in addr_payload["addresses"]:
                        tup = (address["ip"], address["port"])
                        if tup not in visited_addresses:  # make queue more honest ...
                            # FIXME hack to get a sense of onion frequency ...
                            if 'onion' in address['ip']:
                                observe_error(tup, 'ONION')
                                return
                            address_queue.put(tup)
                    logger.info(f'Received {len(addr_payload["addresses"])} addrs from {address["ip"]} after {time.time() - start} seconds')
                    break
            else:
                logger.info(f"Ignoring {msg['command']}")


    logger.info("Exiting")


def simple_worker(worker_id, address_queue, run_for):
    time.sleep(random.random()*5)  # space them out a bit
    logger.info(f"Starting worker #{worker_id}")
    outer_start = time.time()
    while time.time() - outer_start < run_for:  # FIXME: Can't run indefinitely for now
        if address_queue.qsize() == 0:
            return

        logger.info(f'Q contains {address_queue.qsize()}')
        address = next_address(address_queue, visited_addresses)
        logger.info(f'Connecting to {address}')

        # If we can't connect, proceed to next addressf
        try:
            sock, version_payload = handshake(address)
        except Exception as e:
            continue

        # Save the address & version payload
        print(f'Contacted {address[0]}')
        logger.info(f'Contacted {address[0]}')


def threaded(target, addresses, workers, run_for):
    address_queue = Queue()

    for address in addresses:
        address_queue.put(address)

    threads = []

    for worker_id in range(workers):
        thread = Thread(target=target, args=(worker_id, address_queue, run_for))
        thread.start()
        threads.append(thread)

    for thread in threads:
        thread.join()

    print("All threads have finished")


def crawl():
    create_tables()
    addresses = fetch_addresses()
    random.shuffle(addresses)
    print(f'DNS lookups returned {len(addresses)} addresses')
    run_for = 60*60*8
    workers = 500
    threaded(worker, addresses, workers, run_for)
    oc = count_observations()
    observations_per_worker_per_second = (oc / workers) / run_for
    print('Total unique observations: ', oc)
    print('Observations / second: ', oc / run_for)
    print('Observatiosn / worker / second: ', observations_per_worker_per_second)

def recycle():
    import sqlite3
    conn = sqlite3.connect('backup.db')
    # addresses = conn.execute("select ip, port from errors where error = '[Errno 111] Connection refused';").fetchall()
    addresses = conn.execute("select ip, port from errors;").fetchall()
    conn.close()

    random.shuffle(addresses)
    print(f'Sifting through {len(addresses)} addresses for gold!')

    run_for = 60*60*8
    workers = 500
    threaded(simple_worker, addresses, workers, run_for)




if __name__ == '__main__':
    import sys
    command = sys.argv[1]
    eval(f'{command}()')
