import sqlite3
import time

DB_FILE = 'crawler.db'

empty_version_payload = dict.fromkeys(['services', 'sender_timestamp',
    'receiver_services', 'receiver_ip', 'receiver_port', 'sender_services',
    'sender_ip', 'sender_port', 'nonce', 'user_agent', 'latest_block', 'relay'])

create_nodes_table_query = """
CREATE TABLE IF NOT EXISTS nodes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ip TEXT,
    port INT,
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
    execute('DROP TABLE nodes')
    execute('DROP TABLE connections')


def drop_and_create_tables():
    drop_tables()
    create_tables()


def insert_node(query_args):
    query = """
    INSERT OR IGNORE INTO nodes (
        ip, port
    ) VALUES (
        :ip, :port
    )
    """
    return execute(query, query_args)


def insert_connection(query_args):
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
    return execute(query, query_args)


def process_crawler_output(conn):
    # Call insert_node() and note the id
    args = {"ip": conn.address[0], "port": conn.address[1]}
    r = insert_node(args)
    node_id = r.lastrowid

    # Prepare arguments to insert_connection()
    args = conn.__dict__.copy()
    args['node_id'] = node_id
    version_payload = conn.version_payload or empty_version_payload
    args.update(version_payload)
    args['nonce'] = str(args['nonce'])  # HACK
    insert_connection(args)


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
