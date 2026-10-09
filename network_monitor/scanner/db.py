"""
db.py
Handles all SQLite storage: known devices (baseline), connection history,
and generated alerts. Keeping this separate from scanning/detection logic
means whoever builds the dashboard can just import this module too.
"""

import sqlite3
from datetime import datetime
from pathlib import Path

DB_PATH = Path(__file__).parent.parent / "data" / "network_monitor.db"


def get_connection():
    DB_PATH.parent.mkdir(exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    """Create tables if they don't exist yet. Safe to call every startup."""
    conn = get_connection()
    cur = conn.cursor()

    cur.execute("""
        CREATE TABLE IF NOT EXISTS known_devices (
            mac TEXT PRIMARY KEY,
            hostname TEXT,
            vendor TEXT,
            first_seen TEXT,
            last_seen TEXT,
            is_baseline INTEGER DEFAULT 0
        )
    """)

    cur.execute("""
        CREATE TABLE IF NOT EXISTS connection_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            mac TEXT,
            ip TEXT,
            timestamp TEXT,
            bytes_transferred INTEGER DEFAULT 0
        )
    """)

    cur.execute("""
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            mac TEXT,
            ip TEXT,
            alert_type TEXT,
            message TEXT,
            timestamp TEXT,
            acknowledged INTEGER DEFAULT 0
        )
    """)

    conn.commit()
    conn.close()


def upsert_device(mac, ip, hostname="unknown", vendor="unknown"):
    """
    Insert a device if new, or update its last_seen timestamp if it exists.
    Returns True if this is the FIRST time we've ever seen this MAC
    (useful for the detector to know "this is brand new").
    """
    conn = get_connection()
    cur = conn.cursor()
    now = datetime.now().isoformat()

    cur.execute("SELECT mac FROM known_devices WHERE mac = ?", (mac,))
    existing = cur.fetchone()

    if existing:
        if hostname != "unknown":
            cur.execute(
                "UPDATE known_devices SET last_seen = ?, hostname = ? WHERE mac = ?",
                (now, hostname, mac),
            )
        else:
            cur.execute(
                "UPDATE known_devices SET last_seen = ? WHERE mac = ?",
                (now, mac),
            )
        conn.commit()
        conn.close()
        return False
    else:
        cur.execute(
            """INSERT INTO known_devices (mac, hostname, vendor, first_seen, last_seen, is_baseline)
               VALUES (?, ?, ?, ?, ?, 0)""",
            (mac, hostname, vendor, now, now),
        )
        conn.commit()
        conn.close()
        return True


def mark_as_baseline(mac):
    """Promote a device to 'trusted baseline' status (call this after the training period)."""
    conn = get_connection()
    conn.execute("UPDATE known_devices SET is_baseline = 1 WHERE mac = ?", (mac,))
    conn.commit()
    conn.close()


def is_baseline_device(mac):
    conn = get_connection()
    row = conn.execute(
        "SELECT is_baseline FROM known_devices WHERE mac = ?", (mac,)
    ).fetchone()
    conn.close()
    return bool(row and row["is_baseline"] == 1)


def log_connection(mac, ip, bytes_transferred=0):
    conn = get_connection()
    conn.execute(
        "INSERT INTO connection_log (mac, ip, timestamp, bytes_transferred) VALUES (?, ?, ?, ?)",
        (mac, ip, datetime.now().isoformat(), bytes_transferred),
    )
    conn.commit()
    conn.close()


def create_alert(mac, ip, alert_type, message):
    conn = get_connection()
    conn.execute(
        """INSERT INTO alerts (mac, ip, alert_type, message, timestamp, acknowledged)
           VALUES (?, ?, ?, ?, ?, 0)""",
        (mac, ip, alert_type, message, datetime.now().isoformat()),
    )
    conn.commit()
    conn.close()


def get_all_devices():
    conn = get_connection()
    rows = conn.execute("SELECT * FROM known_devices ORDER BY last_seen DESC").fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_recent_alerts(limit=50):
    conn = get_connection()
    rows = conn.execute(
        "SELECT * FROM alerts ORDER BY timestamp DESC LIMIT ?", (limit,)
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_average_bytes_for_device(mac, lookback=20):
    """Used by the detector to check if current traffic is a statistical outlier."""
    conn = get_connection()
    rows = conn.execute(
        """SELECT bytes_transferred FROM connection_log
           WHERE mac = ? ORDER BY timestamp DESC LIMIT ?""",
        (mac, lookback),
    ).fetchall()
    conn.close()
    if not rows:
        return 0
    values = [r["bytes_transferred"] for r in rows]
    return sum(values) / len(values)
