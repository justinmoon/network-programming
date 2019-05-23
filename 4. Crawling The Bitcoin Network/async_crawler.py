from io import BytesIO
import time

import asyncio

from async_lib import (
    read_msg, 
    serialize_msg, 
    serialize_version_payload, 
    read_addr_payload,
    query_dns_seeds,
    handshake,
)



async def get_peers(reader, writer):
    writer.write(serialize_msg(b'getaddr'))
    while True:
        msg = await read_msg(reader)
        command = msg['command']
        payload_len = len(msg['payload'])

        # Respond to "ping"
        if command == b'ping':
            res = serialize_msg(command=b'pong', payload=msg['payload'])
            writer.write(res)

        # Specially handle peer lists
        if command == b'addr':
            payload = read_addr_payload(BytesIO(msg['payload']))
            print('addrs', len(payload['addresses']))
            if len(payload['addresses']) > 1:
                return [
                    (a['ip'], a['port']) for a in payload['addresses']
                ]
    return []


async def visit(loop, address, online):
    writer = None
    try:
        reader, writer = await asyncio.wait_for(handshake(loop, address), timeout=1)
        online.add(address)
        print('handshake successful')
        peers = await asyncio.wait_for(get_peers(reader, writer), timeout=30)
        return peers

    # FIXME
    except Exception as e:
        # raise
        print(e)
        return []
    
    finally:
        if writer:
            writer.close()


async def worker(loop, q, online):
    while True:
        address = await q.get()
        print(f'queue size: {q.qsize()} online: {len(online)}' )
        peers = await visit(loop, address, online)

        for peer in peers:
            await q.put(peer)


async def fill_queue(q):
    addresses = query_dns_seeds()
    for address in addresses:
        await q.put(address)


def main():
    loop = asyncio.get_event_loop()

    online = set()
    offline = set()
    num_workers = 500
    q = asyncio.Queue()

    # start as many workers as we receive dns seeds
    tasks = []
    tasks.append(loop.create_task(fill_queue(q)))
    for address in range(num_workers):
        tasks.append(loop.create_task(worker(loop, q, online, offline)))

    loop.run_until_complete(asyncio.gather(*tasks))
    loop.close()

if __name__ == '__main__':
    main()
