import sqlite3
from datetime import datetime

DB_PATH = "vuln_scanner.db"

def get_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db(conn=None):
    close = conn is None
    if conn is None:
        conn = get_connection()
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS targets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            host TEXT NOT NULL,
            ports TEXT NOT NULL,
            enabled BOOLEAN NOT NULL DEFAULT 1,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target_id INTEGER NOT NULL,
            started_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            finished_at DATETIME,
            status TEXT NOT NULL DEFAULT 'running',
            FOREIGN KEY (target_id) REFERENCES targets(id)
        );
        CREATE TABLE IF NOT EXISTS findings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id INTEGER NOT NULL,
            target_id INTEGER NOT NULL,
            port INTEGER NOT NULL,
            script_name TEXT NOT NULL,
            output TEXT NOT NULL,
            severity TEXT NOT NULL,
            first_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
            resolved BOOLEAN NOT NULL DEFAULT 0,
            FOREIGN KEY (scan_id) REFERENCES scans(id),
            FOREIGN KEY (target_id) REFERENCES targets(id)
        );
    """)
    conn.commit()
    if close:
        conn.close()

def add_target(conn, host, ports):
    conn.execute("INSERT INTO targets (host, ports) VALUES (?, ?)", (host, ports))
    conn.commit()

def get_targets(conn):
    return conn.execute(
        "SELECT * FROM targets WHERE enabled=1 ORDER BY created_at DESC"
    ).fetchall()

def delete_target(conn, target_id):
    conn.execute("DELETE FROM targets WHERE id=?", (target_id,))
    conn.commit()

def add_scan(conn, target_id):
    cur = conn.execute("INSERT INTO scans (target_id) VALUES (?)", (target_id,))
    conn.commit()
    return cur.lastrowid

def update_scan(conn, scan_id, status):
    conn.execute(
        "UPDATE scans SET status=?, finished_at=? WHERE id=?",
        (status, datetime.now().isoformat(), scan_id)
    )
    conn.commit()

def add_finding(conn, scan_id, target_id, port, script_name, output, severity):
    existing = conn.execute(
        "SELECT id FROM findings WHERE target_id=? AND port=? AND script_name=? AND resolved=0",
        (target_id, port, script_name)
    ).fetchone()
    if existing:
        return False
    conn.execute(
        "INSERT INTO findings (scan_id, target_id, port, script_name, output, severity) VALUES (?,?,?,?,?,?)",
        (scan_id, target_id, port, script_name, output, severity)
    )
    conn.commit()
    return True

def get_findings(conn, resolved=False):
    return conn.execute(
        """SELECT f.*, t.host
           FROM findings f
           JOIN targets t ON f.target_id=t.id
           WHERE f.resolved=?
           ORDER BY f.first_seen DESC""",
        (1 if resolved else 0,)
    ).fetchall()

def get_scan_history(conn):
    return conn.execute(
        """SELECT s.*, t.host,
           (SELECT COUNT(*) FROM findings WHERE scan_id=s.id) AS finding_count
           FROM scans s
           JOIN targets t ON s.target_id=t.id
           ORDER BY s.started_at DESC"""
    ).fetchall()

def resolve_finding(conn, finding_id):
    conn.execute("UPDATE findings SET resolved=1 WHERE id=?", (finding_id,))
    conn.commit()