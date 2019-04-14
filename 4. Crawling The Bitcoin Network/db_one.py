import sqlite3
import time

DB_FILE = 'crawler.db'

empty_version_payload = dict.fromkeys(['version', 'services', 'sender_timestamp',
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
    start INT,
    version INT,
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
    from mycrawler import Node
    return Node(**dict_factory(cursor, row))


def execute(statement, args={}, row_factory=None):
    with sqlite3.connect(DB_FILE) as conn:
        if row_factory:
            conn.row_factory = row_factory
        return conn.execute(statement, args)


def create_tables():
    execute(create_nodes_table_query)
    execute(create_connections_table_query)


def drop_tables():
    execute('DROP TABLE IF EXISTS nodes')
    execute('DROP TABLE IF EXISTS connections')


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
        (version, start, services, sender_timestamp, receiver_services, 
        receiver_ip, receiver_port, sender_services, sender_ip, sender_port, 
        nonce, user_agent, latest_block, relay, node_id)
    VALUES
        (:version, :start, :services, :sender_timestamp, 
         :receiver_services, :receiver_ip, :receiver_port, :sender_services, :sender_ip, 
         :sender_port, :nonce, :user_agent, :latest_block, :relay, :node_id)
    """
    return execute(query, query_args)


def next_nodes(n):
    return execute(
        """
        SELECT *
        FROM nodes
        WHERE id NOT IN (SELECT node_id FROM connections)
        LIMIT ?""",
        (n,),
        row_factory=node_factory
    ).fetchall()


def nodes_visited():
    return execute(
        """SELECT COUNT(DISTINCT node_id)
        FROM connections
        WHERE services IS NOT null"""
    ).fetchone()[0]


def nodes_total():
    return execute(
        "SELECT COUNT(*) FROM nodes"
    ).fetchone()[0]
