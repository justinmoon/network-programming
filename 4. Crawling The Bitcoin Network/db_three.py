import sqlite3
import time

from crawler import Node

DB_FILE = 'crawler.db'
ONE_HOUR = 60*60

empty_version_payload = dict.fromkeys(['services', 'sender_timestamp',
    'receiver_services', 'receiver_ip', 'receiver_port', 'sender_services',
    'sender_ip', 'sender_port', 'nonce', 'user_agent', 'latest_block', 'relay'])

create_nodes_table_query = """
CREATE TABLE IF NOT EXISTS nodes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ip TEXT,
    port INT,
    next_connection_at INT,
    connections_missed INT,
    UNIQUE(ip, port)
)
"""

create_connections_table_query = """
CREATE TABLE IF NOT EXISTS connections (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    handshake_start INT,
    handshake_end INT,
    services INT,
    sender_timestamp INT,
    receiver_services INT,
    receiver_ip TEXT,
    receiver_port INT,
    sender_services INT,
    sender_ip TEXT,
    sender_port INT,
    nonce TEXT,
    user_agent TEXT,
    latest_block INT,
    relay INT,
    node_id INT,
    FOREIGN KEY(node_id) REFERENCES nodes(id)
)
"""


def dict_factory(cursor, row):
    d = {}
    for idx, col in enumerate(cursor.description):
        d[col[0]] = row[idx]
    return d


def node_factory(cursor, row):
    return Node(**dict_factory(cursor, row))


def execute(statement, args={}, row_factory=None):
    with sqlite3.connect(DB_FILE) as conn:
        if row_factory:
            conn.row_factory = row_factory
        return conn.execute(statement, args)


def executemany(statement, args={}, row_factory=None):
    with sqlite3.connect(DB_FILE) as conn:
        if row_factory:
            conn.row_factory = row_factory
        return conn.executemany(statement, args)


def create_tables():
    execute(create_nodes_table_query)
    execute(create_connections_table_query)


def drop_tables():
    execute('DROP TABLE IF EXISTS nodes')
    execute('DROP TABLE IF EXISTS connections')


def drop_and_create_tables():
    drop_tables()
    create_tables()


def insert_nodes(query_args):
    query = """
    INSERT OR IGNORE INTO nodes (
        ip, port, next_connection_at, connections_missed
    ) VALUES (
        :ip, :port, :next_connection_at, :connections_missed
    )
    """
    return executemany(query, query_args)


def update_nodes(query_args):
    query = """
    UPDATE nodes
    SET 
        next_connection_at = :next_connection_at,
        connections_missed = :connections_missed
    WHERE
        id = :id
    """
    return executemany(query, query_args)


def insert_connections(query_args):
    query = """
    INSERT INTO connections
        (handshake_start, handshake_end, services, sender_timestamp, receiver_services,
        receiver_ip, receiver_port, sender_services, sender_ip, sender_port,
        nonce, user_agent, latest_block, relay, node_id)
    VALUES
        (:handshake_start, :handshake_end, :services, :sender_timestamp,
         :receiver_services, :receiver_ip, :receiver_port, :sender_services, :sender_ip,
         :sender_port, :nonce, :user_agent, :latest_block, :relay, :node_id)
    """
    return executemany(query, query_args)


def record_worker_outputs(connections):
    start = time.time()

    insert_nodes_args = []
    update_nodes_args = []
    insert_connections_args = []

    for conn in connections:
        # Prepare arguments to insert_nodes()
        insert_nodes_args.extend([node.__dict__ for node in conn.nodes_discovered])

        # Prepare arguments to update_nodes()
        if conn.version_payload:
            # If they were online, schedule another visit in 1 hour
            conn.node.next_connection_at = time.time() + ONE_HOUR
            conn.node.connections_missed = 0
        else:
            # If they were online, schedule another visit with double the wait as last time
            conn.node.next_connection_at = time.time() + 2**conn.node.connections_missed * ONE_HOUR
            conn.node.connections_missed = conn.node.connections_missed + 1
        update_nodes_args.append(conn.node.__dict__)

        # Prepare arguments to update_connections()
        insert_connections_arg = conn.__dict__.copy()
        insert_connections_arg['node_id'] = conn.node.id
        version_payload = conn.version_payload or empty_version_payload
        insert_connections_arg.update(version_payload)
        insert_connections_arg['nonce'] = str(insert_connections_arg['nonce']) # HACK
        insert_connections_args.append(insert_connections_arg)

    # Write to db
    insert_nodes(insert_nodes_args)
    update_nodes(update_nodes_args)
    insert_connections(insert_connections_args)
    print(f'processing took {time.time() - start} on {len(conn.nodes_discovered)} nodes discovered')


def nodes_due(num_nodes):
    # Get every node that is past due for a visit
    now = time.time()
    query = '''
    SELECT * FROM nodes
    WHERE next_connection_at < ?
    ORDER BY next_connection_at ASC
    LIMIT ?
    '''
    return execute(
        query,
        args=(now, num_nodes),
        row_factory=node_factory,
    ).fetchall()


def count_nodes():
    query = """
        select count(distinct node_id) 
        from connections 
        where 
            handshake_end is not null and
            handshake_end > ?
    """
    yesterday = time.time() - 60*60*24
    return execute(query, (yesterday,)).fetchone()[0]
