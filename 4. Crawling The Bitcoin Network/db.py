import contextlib
import os
import random
import sqlite3
import threading
import time

def execute_statement(statement, args={}):
    with contextlib.closing(sqlite3.connect("crawler.db")) as conn: # auto-closes
        with conn: # auto-commits
            with contextlib.closing(conn.cursor()) as cursor: # auto-closes
                return cursor.execute(statement, args).fetchall()

def create_table(remove=False):
    filename = "crawler.db"
    
    try:
        os.remove(filename)
    except Exception as e:
        print(e)
        pass

    q = """
    CREATE TABLE observations (
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
    execute_statement(q)
            
            
def observe_node(address, args_dict):
    q = """
    INSERT INTO observations (
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
    execute_statement(q, args_dict)

def count_observations(filename="crawler.db"):
    with sqlite3.connect("crawler.db") as conn:
        return conn.execute("select count(*) from observations").fetchone()[0]
    
def list_observations():
    with sqlite3.connect("crawler.db") as conn:
        return conn.execute("select * from observations").fetchone()
    
