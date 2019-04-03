import threading, time, random


def connect_to_peer(i):
    print(f'connecting to peer {i}')
    seconds = random.random()
    time.sleep(seconds)
    print(f'finished with peer {i} after {seconds}')


for i in range(10):
    # synchronous
    # connect_to_peer(i)

    # asynchronous
    thread = threading.Thread(target=connect_to_peer, args=(i,))
    thread.start()
