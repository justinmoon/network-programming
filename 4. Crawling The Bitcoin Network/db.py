import sqlite3
import time

DB_FILE = 'crawler.db'
ONE_HOUR = 60 * 60

empty_version_payload = dict.fromkeys(['version', 'services', 'sender_timestamp',
    'receiver_services', 'receiver_ip', 'receiver_port', 'sender_services',
    'sender_ip', 'sender_port', 'nonce', 'user_agent', 'latest_block', 'relay'])

create_nodes_table_query = """
CREATE TABLE IF NOT EXISTS nodes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ip TEXT,
    port INT,
    next_visit INT,
    visits_missed INT,
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
        ip, port, next_visit, visits_missed
    ) VALUES (
        :ip, :port, :next_visit, :visits_missed
    )
    """
    return executemany(query, query_args)


def update_nodes(query_args):
    query = """
    UPDATE nodes
    SET 
        next_visit = :next_visit,
        visits_missed = :visits_missed
    WHERE
        id = :id
    """
    return executemany(query, query_args)


def insert_connections(query_args):
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
    return executemany(query, query_args)


def process_crawler_outputs(conns):
    # Initialize arguments to insert_x functions
    insert_nodes_args = []
    update_nodes_args = []
    insert_connections_args = []

    for conn in conns:
        # Prepare args to insert_nodes() from newly discovered nodes
        for node in conn.nodes_discovered:
            insert_nodes_args.append(node.__dict__)

        # Prepare args to insert_connections()
        if conn.peer_version_payload:
            args = conn.peer_version_payload.copy()
            args['nonce'] = str(args['nonce'])  # HACK
        else:
            args = empty_version_payload.copy()
        args['start'] = conn.start
        args['node_id'] = conn.node.id
        insert_connections_args.append(args)

        # Prepare args to update_nodes()
        if conn.peer_version_payload:
            # If online, schedule another visit in 1 hour
            conn.node.next_visit = time.time() + ONE_HOUR
            conn.node.visits_missed = 0
        else:
            # If offline, double wait until next visit
            conn.node.next_visit = time.time() + 2**conn.node.visits_missed * ONE_HOUR
            conn.node.visits_missed += 1
        update_nodes_args.append(conn.node.__dict__)

    # Hit the database
    insert_nodes(insert_nodes_args)
    update_nodes(update_nodes_args)
    insert_connections(insert_connections_args)


def next_nodes(n):
    now = time.time()
    return execute(
        """
        SELECT *
        FROM nodes
        where next_visit < ?
        ORDER BY next_visit ASC
        LIMIT ?""",
        (now, n,),
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
