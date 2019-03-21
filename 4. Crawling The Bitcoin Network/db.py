import contextlib
import sqlite3
import time

db_file = 'crawler.db'


conn = sqlite3.connect(db_file)

try:
    RUN = conn.execute('select max(run) from observations;').fetchone()[0] + 1
except Exception as e:
    print('error initializing "RUN":', e)
    RUN = 0

print(f'RUN is {RUN}')


def execute_statement(statement, args={}, retries=3):
    # try / except is a hack for write conflicts from multiple threads
    with sqlite3.connect('crawler.db') as conn:
        return conn.execute(statement, args).fetchall()

def create_tables(remove=False):
    create_observations_table = """
    CREATE TABLE IF NOT EXISTS observations (
        run INT,
        ip TEXT,
        port INT,
        services INT,
        timestamp INT,
        receiver_services INT,
        receiver_ip TEXT,
        receiver_port INT,
        sender_services INT,
        sender_ip TEXT,
        sender_port INT,
        nonce TEXT,
        user_agent TEXT,
        latest_block INT,
        relay INT
    )
    """
    execute_statement(create_observations_table)

    create_errors_table = """
    CREATE TABLE IF NOT EXISTS errors (
        run INT,
        ip TEXT,
        port INT,
        error INT,
        timestamp INT
    )
    """
    execute_statement(create_errors_table)

            
def observe_node(address, args_dict):
    q = """
    INSERT INTO observations (
        run,
        ip,
        port,
        services,
        timestamp,
        receiver_services,
        receiver_ip,
        receiver_port,
        sender_services,
        sender_ip,
        sender_port,
        nonce,
        user_agent,
        latest_block,
        relay
    ) VALUES (
        :run,
        :ip,
        :port,
        :services,
        :timestamp,
        :receiver_services,
        :receiver_ip,
        :receiver_port,
        :sender_services,
        :sender_ip,
        :sender_port,
        :nonce,
        :user_agent,
        :latest_block,
        :relay
    )
    """
    args_dict["nonce"] = str(args_dict["nonce"]) # HACK
    args_dict["ip"] = address[0]
    args_dict["port"] = address[1]
    args_dict["run"] = RUN
    execute_statement(q, args_dict)


def observe_error(address, error):
    q = """
    INSERT INTO errors (
        run, ip, port, error, timestamp
    ) VALUES (
        ?,?,?,?,?
    )
    """
    ip, port = address
    timestamp = time.time()
    execute_statement(q, (RUN, ip, port, error, timestamp))


def fetch_visited_addrs():
    with sqlite3.connect(db_file) as conn:
        return conn.execute("select distinct ip, port from observations").fetchall()


def total_observations():
    with sqlite3.connect(db_file) as conn:
        return conn.execute("select count(distinct ip) from observations").fetchone()[0]

def last_run_observations():
    with sqlite3.connect(db_file) as conn:
        q = """
        select count(distinct ip) 
        from observations
        where run = (select max(run) from observations);
        """
        return conn.execute(q).fetchone()[0]

def new_observations():
    with sqlite3.connect(db_file) as conn:
        # Hacky ...
        q = """
        select count(distinct ip) 
        from observations
        where run = (select max(run) from observations)
        and ip not in ( 
            select ip from observations where run < (select max(run) from observations)
        )
        """
        return conn.execute(q).fetchone()[0]
