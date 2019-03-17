import os
import time
import logging
import random

from io import BytesIO
from queue import Queue
from threading import Thread, Lock

from lib import (
    serialize_version_payload, serialize_msg, read_version_payload, read_msg,
    read_addr_payload, connect, fetch_addresses
)
from db import observe_node, observe_error, create_tables, fetch_visited_addrs
from report import report


logging.basicConfig(level="INFO", filename='crawler.log',
    format='%(threadName)-6s %(asctime)s %(message)s')
logger = logging.getLogger(__name__)


class Connection:

    def __init__(self, address, timeout=30):
        self.address = address
        self.start = None
        self.timeout = timeout
        self.sock = None
        self.finished = False

        # Results
        self.version_payload = None
        self.addresses = []

    def timed_out(self):
        return time.time() > self.start + self.timeout

    def send_version(self):
        payload = serialize_version_payload()
        msg = serialize_msg(b"version", payload)
        self.sock.sendall(msg)

    def send_verack(self):
        msg = serialize_msg(b"verack", b"")
        self.sock.sendall(msg)

    def send_getaddr(self):
        self.sock.send(serialize_msg(b"getaddr", b""))

    def handle_version(self, stream):
        # Interpret payload stream
        self.version_payload = read_version_payload(stream)

        # Save the address & version payload
        observe_node(self.address, self.version_payload)

        # Complete handshake with a `verack`
        self.send_verack()

    def handle_verack(self, stream):
        # With connection established, ask for their peer list
        self.send_getaddr()

    def handle_addr(self, stream):
        # If we receive more than 1, save to queue and mark `self.finished = True`
        addr_payload = read_addr_payload(stream)
        if len(addr_payload["addresses"]) > 1:
            # Record addresses, Crawler will persist these
            self.addresses = [(a['ip'], a['port']) for a in addr_payload['addresses']]

            # FIXME: this is noisy
            num_addrs = len(addr_payload["addresses"])
            ip = self.address[0]
            duration = time.time() - self.start
            logger.info(f'Received {num_addrs} addrs from {ip} after {duration} seconds')
            self.finished = True

    def handle_msg(self, msg):
        command_str = msg['command'].decode('utf-8')
        method = f"handle_{command_str}"
        if hasattr(self, method):
            stream = BytesIO(msg['payload'])
            getattr(self, method)(stream)

    def open(self):
        self.start = time.time()

        # Establish TCP connection
        self.sock = connect(self.address)
        stream = self.sock.makefile("rb")

        # Start handshake
        self.send_version()

        # Handle messages until time runs out
        while not self.timed_out() and not self.finished:
            msg = read_msg(stream)
            self.handle_msg(msg)

    def close(self):
        self.finished = False
        self.sock.close()


class Crawler:

    def __init__(self, address_queue):
        self.address_queue = address_queue
        self.visited = set()
        self.lock = Lock()


    def observe_node(self, connection):
        observe_node(connection.address, connection.version_payload)

    def get_address(self):
        """Find an address we haven't visited yet"""
        while not self.address_queue.empty():
            address = self.address_queue.get()
            if address not in self.visited:
                with self.lock:
                    self.visited.add(address)
                return address

    def put_addresses(self, addresses):
        """Dump addresses in the queue"""
        for address in addresses:
            if address not in self.visited:
                self.address_queue.put(address)

    def crawl(self):
        while True:
            address = self.get_address()

            if not address:  # FIXME better way to exit threads
                return

            try:
                connection = Connection(address)
                connection.open()
            except Exception as e:
                logging.info(str(e))
                observe_error(address, str(e))
                continue

            connection.close()
            self.observe_node(connection)
            self.put_addresses(connection.addresses)


def threaded_crawler(address_queue):

    # Run it
    num_threads = 2000
    threads = []

    def target():
        return Crawler(address_queue).crawl()

    for _ in range(num_threads):
        thread = Thread(target=target)
        thread.start()
        threads.append(thread)

    # Generate a little report until the script finishes
    while True:

        # Break out of loop if all threads are dead
        if True not in set([t.is_alive() for t in threads]):
            break

        # Clear terminal window and print fresh report
        os.system('cls' if os.name == 'nt' else 'clear')
        report(threads, address_queue)
        time.sleep(2)

    print("All threads have finished")


def synchronous_crawler(address_queue, visited):
    return Crawler(address_queue, visited).crawl()


def main():
    # Make sure database is set up
    create_tables()

    # Get addresses, shuffle them, create and fill the queue
    addresses = fetch_addresses()
    logger.info(f'DNS lookups returned {len(addresses)} addresses')
    random.shuffle(addresses)
    address_queue = Queue()
    for address in addresses:
        address_queue.put(address)

    # Run it
    # synchronous_crawler(address_queue)
    threaded_crawler(address_queue)


if __name__ == '__main__':
    main()
