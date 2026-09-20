"""
api/db.py — minimal persistence layer using stdlib sqlite3.

Two tables:
  users        (id, username, password_hash, created_at)
  scan_history (id, user_id, url, score, grade, scanned_at, result_json)

No ORM — this app's data needs are simple enough that sqlite3 + plain
SQL is easier to reason about than adding SQLAlchemy as a dependency.
DB_PATH is overridable via env var so tests can point at a throwaway file.
"""

import json
import os
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone

DB_PATH = os.environ.get("VULNSCAN_DB_PATH", os.path.join(os.path.dirname(__file__), "vulnscan.db"))

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS scan_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    task_id TEXT UNIQUE NOT NULL,
    url TEXT NOT NULL,
    score INTEGER NOT NULL,
    grade TEXT NOT NULL,
    scanned_at TEXT NOT NULL,
    result_json TEXT NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(id)
);
"""


@contextmanager
def get_connection(db_path: str = None):
    conn = sqlite3.connect(db_path or DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def init_db(db_path: str = None):
    with get_connection(db_path) as conn:
        conn.executescript(SCHEMA)


def create_user(username: str, password_hash: str, db_path: str = None) -> int:
    """Returns the new user's id. Raises sqlite3.IntegrityError if username is taken."""
    with get_connection(db_path) as conn:
        cursor = conn.execute(
            "INSERT INTO users (username, password_hash, created_at) VALUES (?, ?, ?)",
            (username, password_hash, datetime.now(timezone.utc).isoformat()),
        )
        return cursor.lastrowid


def get_user_by_username(username: str, db_path: str = None):
    with get_connection(db_path) as conn:
        row = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
        return dict(row) if row else None


def get_user_by_id(user_id: int, db_path: str = None):
    with get_connection(db_path) as conn:
        row = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
        return dict(row) if row else None


def save_scan_to_history(user_id: int, task_id: str, scan_result: dict, db_path: str = None) -> int:
    """
    Stores a completed scan (the same dict run_scan() returns) tied to a user.
    Idempotent on task_id — calling this twice for the same scan (e.g. the
    frontend retries the save request) returns the existing row instead of
    creating a duplicate history entry.
    """
    report = scan_result["report"]
    with get_connection(db_path) as conn:
        cursor = conn.execute(
            """INSERT OR IGNORE INTO scan_history
               (user_id, task_id, url, score, grade, scanned_at, result_json)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (
                user_id, task_id, scan_result["url"], report["score"], report["grade"],
                datetime.now(timezone.utc).isoformat(), json.dumps(scan_result),
            ),
        )
        if cursor.rowcount == 0:
            existing = conn.execute(
                "SELECT id FROM scan_history WHERE task_id = ?", (task_id,)
            ).fetchone()
            return existing["id"]
        return cursor.lastrowid


def get_history_for_user(user_id: int, db_path: str = None) -> list:
    """Returns scans newest-first, without the full result_json blob (listing view)."""
    with get_connection(db_path) as conn:
        rows = conn.execute(
            """SELECT id, url, score, grade, scanned_at FROM scan_history
               WHERE user_id = ? ORDER BY scanned_at DESC""",
            (user_id,),
        ).fetchall()
        return [dict(row) for row in rows]


def get_scan_detail(scan_history_id: int, user_id: int, db_path: str = None):
    """Returns the full stored result for one history entry, scoped to its owner."""
    with get_connection(db_path) as conn:
        row = conn.execute(
            "SELECT * FROM scan_history WHERE id = ? AND user_id = ?",
            (scan_history_id, user_id),
        ).fetchone()
        if not row:
            return None
        data = dict(row)
        data["result"] = json.loads(data.pop("result_json"))
        return data
