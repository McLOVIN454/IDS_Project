#!/usr/bin/env python3

# Database layer: creates the SQLite database and provides functions for
# saving captured packets/threat-intel hits and reading them back.

import sqlite3
import threading
import time

DB_PATH = "traffic.db"

# save_packet() runs once per captured packet, potentially hundreds of
# times a second. Opening a new connection every call was a real
# bottleneck, so each writing thread gets ONE reusable connection instead,
# stored per-thread since SQLite connections can't be shared across threads.
_write_connections = threading.local()

# How many days of packets to keep. Kept longer than detector.py's 7-day
# learning period, so pruning never resets a device back to "new" again.
RETENTION_DAYS = 30

# save_packet()/save_flagged_ip() batch their commits instead of committing
# after every single insert - a commit once every 50 packets, or once a
# second, whichever comes first. This cuts disk writes a lot under heavy
# traffic. Trade-off: up to this many packets (or this much time) since
# the last commit could be lost on an unclean crash or power loss, and new
# rows stay invisible to other connections (the dashboard/detector) until
# the batch commits.
COMMIT_BATCH_SIZE = 50
COMMIT_INTERVAL_SECONDS = 1.0


def get_connection():
    return sqlite3.connect(DB_PATH)


def init_db():
    # Create the packets table (captured traffic) and the flagged_ips
    # table (threat-intel hits), only if they don't already exist.
    conn = get_connection()
    conn.execute(
        "CREATE TABLE IF NOT EXISTS packets ("
        "id INTEGER PRIMARY KEY AUTOINCREMENT, "
        "ts REAL, mac TEXT, src_ip TEXT, dst_ip TEXT, proto TEXT, "
        "port INTEGER, size INTEGER, dns_query TEXT)"
    )
    conn.execute(
        "CREATE TABLE IF NOT EXISTS flagged_ips ("
        "id INTEGER PRIMARY KEY AUTOINCREMENT, "
        "ts REAL, ip TEXT, src_ip TEXT, dst_ip TEXT)"
    )
    # Speeds up delete_old_packets()'s "WHERE ts < ?" and any ORDER BY ts
    # query - without this, both require a full table scan once the
    # packets table gets into the millions of rows. On an existing large
    # database this index takes a moment to build the first time it runs,
    # then it's a one-time cost.
    conn.execute("CREATE INDEX IF NOT EXISTS idx_packets_ts ON packets(ts)")
    conn.commit()
    conn.close()


def _get_write_connection():
    # Hand back this thread's reusable connection, opening one (with
    # faster write settings) the first time this thread calls it.
    if not hasattr(_write_connections, "conn"):
        conn = sqlite3.connect(DB_PATH)
        # WAL mode lets writes happen without locking out readers, and
        # synchronous=NORMAL trades a small amount of crash-safety for a
        # big write-speed improvement - a fair trade for packet logs.
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=NORMAL")
        _write_connections.conn = conn
        _write_connections.pending = 0
        _write_connections.last_commit = time.time()
    return _write_connections.conn


def _commit_if_due(conn):
    # Commits once COMMIT_BATCH_SIZE inserts have piled up, or once
    # COMMIT_INTERVAL_SECONDS have passed since the last commit - whichever
    # comes first. Bounds both the crash-loss window and how long new rows
    # stay invisible to other connections.
    _write_connections.pending += 1
    now = time.time()
    due = (
        _write_connections.pending >= COMMIT_BATCH_SIZE
        or (now - _write_connections.last_commit) >= COMMIT_INTERVAL_SECONDS
    )
    if due:
        conn.commit()
        _write_connections.pending = 0
        _write_connections.last_commit = now


def save_packet(ts, mac, src_ip, dst_ip, proto, port, size, dns_query=None):
    conn = _get_write_connection()
    conn.execute(
        "INSERT INTO packets (ts, mac, src_ip, dst_ip, proto, port, size, dns_query) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        (ts, mac, src_ip, dst_ip, proto, port, size, dns_query),
    )
    _commit_if_due(conn)


def save_flagged_ip(ts, ip, src_ip, dst_ip):
    # `ip` is whichever of src_ip/dst_ip matched the threat-intel
    # blocklist; src_ip/dst_ip are kept too so the dashboard/notification
    # can show who was talking to the bad IP, not just the bad IP alone.
    conn = _get_write_connection()
    conn.execute(
        "INSERT INTO flagged_ips (ts, ip, src_ip, dst_ip) VALUES (?, ?, ?, ?)",
        (ts, ip, src_ip, dst_ip),
    )
    _commit_if_due(conn)


def flush_writes():
    # Forces this thread's pending batched writes to commit right now,
    # regardless of the batch size/interval - for anywhere an up-to-the-
    # moment read needs to see what was just written (used below, and
    # handy for manual testing).
    if hasattr(_write_connections, "conn") and _write_connections.pending:
        _write_connections.conn.commit()
        _write_connections.pending = 0
        _write_connections.last_commit = time.time()


def get_flagged_ips():
    conn = get_connection()
    cursor = conn.execute("SELECT * FROM flagged_ips ORDER BY ts ASC")
    rows = cursor.fetchall()
    conn.close()
    return rows


def get_flagged_ips_since(last_id):
    # Only rows newer than last_id - lets detector.py process just the
    # threat-intel hits it hasn't seen yet, instead of the whole table.
    conn = get_connection()
    cursor = conn.execute(
        "SELECT * FROM flagged_ips WHERE id > ? ORDER BY id ASC", (last_id,)
    )
    rows = cursor.fetchall()
    conn.close()
    return rows


def get_recent_packets(limit=10):
    # Ordered by id (the primary key, already indexed) rather than ts -
    # packets are inserted in capture order, so this gives the same result
    # as ordering by ts but without needing to sort the whole table.
    conn = get_connection()
    cursor = conn.execute(
        "SELECT * FROM packets ORDER BY id DESC LIMIT ?", (limit,)
    )
    rows = cursor.fetchall()
    conn.close()
    return rows


def get_all_packets():
    # Oldest first - the detector replays history in the order it
    # actually happened to build up each device's baseline.
    conn = get_connection()
    cursor = conn.execute("SELECT * FROM packets ORDER BY ts ASC")
    rows = cursor.fetchall()
    conn.close()
    return rows


def get_max_packet_id():
    # Highest id currently in packets, or 0 if the table is empty. Used by
    # detector.py right after startup to skip straight to "watch for new
    # packets from here" instead of pulling the entire table into memory
    # at once, which is what crashed the Pi.
    conn = get_connection()
    cursor = conn.execute("SELECT MAX(id) FROM packets")
    result = cursor.fetchone()[0]
    conn.close()
    return result or 0


def get_max_flagged_id():
    # Same idea as get_max_packet_id(), for the flagged_ips table.
    conn = get_connection()
    cursor = conn.execute("SELECT MAX(id) FROM flagged_ips")
    result = cursor.fetchone()[0]
    conn.close()
    return result or 0


def get_packets_since(last_id):
    # Only rows newer than last_id - lets detector.py process just the
    # packets it hasn't seen yet instead of replaying the entire table on
    # every single call, which is what made the dashboard slow once
    # traffic.db grew into the millions of rows.
    conn = get_connection()
    cursor = conn.execute(
        "SELECT * FROM packets WHERE id > ? ORDER BY id ASC", (last_id,)
    )
    rows = cursor.fetchall()
    conn.close()
    return rows


def delete_old_packets(days=RETENTION_DAYS):
    cutoff = time.time() - (days * 24 * 60 * 60)
    conn = get_connection()
    conn.execute("DELETE FROM packets WHERE ts < ?", (cutoff,))
    conn.commit()
    conn.close()


if __name__ == "__main__":
    # Quick manual test: set up the tables, save one fake packet, read it
    # back and print it - confirms this file works before wiring it in.
    init_db()
    save_packet(
        ts=1234567890.0,
        mac="aa:bb:cc:dd:ee:ff",
        src_ip="192.168.1.50",
        dst_ip="1.1.1.1",
        proto="TCP",
        port=443,
        size=512,
        dns_query=None,
    )
    flush_writes()
    print("Saved a test packet. Recent packets in the database:")
    for row in get_recent_packets():
        print(row)
