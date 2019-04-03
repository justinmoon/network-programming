import threading, time, random


def connect(address):
    print(f'connecting to peer {address}')
    seconds = random.random()
    time.sleep(seconds)
    print(f'finished with peer {address} after {seconds}')


class Connection:

    def __init__(self, address):
        self.address = address

    def open(self):
        connect(self.address)

class ConnectionWorker(threading.Thread):

    def __init__(self, address):
        threading.Thread.__init__(self)
        self.address = address

    def run(self):
        connect(self.address)


for i in range(10):
    print('synchronous')
    connect(i)

    # print('asynchronous w/ function')
    # thread = threading.Thread(target=connect, args=(i,))
    # thread.start()

    # print('asynchronous w/ class')
    # def target():
        # return Connection(i).open()
    # thread = threading.Thread(target=target)
    # thread.start()

    # print('asynchronous threading.Thread subclass')
    # conn = ConnectionWorker(i)
    # conn.start()
