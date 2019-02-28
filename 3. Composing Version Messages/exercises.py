import time
from random import randint

ZERO = b'\x00'

dummy_address = {
    "services": 0,
    "ip": '0.0.0.0',
    "port": 8333
}

def serialize_version_payload(
        version=70015, services=0, timestamp=None,
        receiver_address=dummy_address,
        sender_address=dummy_address,
        nonce=None, user_agent=b'/buidl-army/',
        start_height=0, relay=True):
    if timestamp is None:
        timestamp = int(time.time())
    if nonce is None:
        nonce = randint(0, 2**64)
    # message starts empty, we add to it for every field
    msg = b''
    # version
    msg += ZERO * 4
    # services
    msg += ZERO * 8
    # timestamp
    msg += ZERO * 8
    # receiver address
    msg += ZERO * 26
    # sender address
    msg += ZERO * 26
    # nonce
    msg += ZERO * 8
    # user agent
    msg += ZERO * 1 # zero byte signifies an empty varstr
    # start height
    msg += ZERO * 4
    # relay
    msg += ZERO * 1
    return msg 