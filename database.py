"""
database.py — SQLite data layer for VaultAI.

Tables:
  users       — master account credentials & encryption salt
  credentials — AES-encrypted vault entries
  audit_log   — immutable security event log

All queries use parameterised statements to prevent SQL injection.
"""

import sqlite3
import os
from datetime import datetime, timezone
from contextlib import contextmanager
from typing import Optional

from config import DB_PATH
from utils.logger import logger


# ─── Connection Factory ───────────────────────────────────────────────────────

@contextmanager
def get_connection():
    """Thread-safe SQLite connection with WAL mode for concurrency."""
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row          # dict-like rows
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


# ─── Schema Init ──────────────────────────────────────────────────────────────

def init_db() -> None:
    """Create tables if they don't exist. Safe to call on every startup."""
    with get_connection() as conn:
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS users (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                username      TEXT    NOT NULL UNIQUE,
                password_hash TEXT    NOT NULL,          -- bcrypt hash
                salt          BLOB    NOT NULL,          -- PBKDF2 salt (32 bytes)
                created_at    TEXT    NOT NULL DEFAULT (datetime('now')),
                last_login    TEXT
            );

            CREATE TABLE IF NOT EXISTS credentials (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id       INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                website       TEXT    NOT NULL,
                username      TEXT    NOT NULL,
                password_enc  TEXT    NOT NULL,          -- AES-256 encrypted
                notes_enc     TEXT,                      -- optional AES-256 encrypted notes
                category      TEXT    DEFAULT 'General',
                created_at    TEXT    NOT NULL DEFAULT (datetime('now')),
                updated_at    TEXT    NOT NULL DEFAULT (datetime('now'))
            );

            CREATE INDEX IF NOT EXISTS idx_creds_user
                ON credentials(user_id);

            CREATE TABLE IF NOT EXISTS audit_log (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id    INTEGER REFERENCES users(id) ON DELETE SET NULL,
                event      TEXT    NOT NULL,
                detail     TEXT,
                ip_hint    TEXT,
                ts         TEXT    NOT NULL DEFAULT (datetime('now'))
            );
        """)
    logger.info("Database initialised at %s", DB_PATH)


# ─── User Operations ──────────────────────────────────────────────────────────

def create_user(username: str, password_hash: str, salt: bytes) -> int:
    """Insert a new user. Returns the new user ID."""
    with get_connection() as conn:
        cur = conn.execute(
            "INSERT INTO users (username, password_hash, salt) VALUES (?, ?, ?)",
            (username, password_hash, salt),
        )
        user_id = cur.lastrowid
    log_event(user_id, "USER_CREATED", f"username={username}")
    return user_id


def get_user_by_username(username: str) -> Optional[sqlite3.Row]:
    with get_connection() as conn:
        return conn.execute(
            "SELECT * FROM users WHERE username = ?", (username,)
        ).fetchone()


def update_last_login(user_id: int) -> None:
    now = datetime.now(timezone.utc).isoformat()
    with get_connection() as conn:
        conn.execute(
            "UPDATE users SET last_login = ? WHERE id = ?", (now, user_id)
        )


# ─── Credential CRUD ──────────────────────────────────────────────────────────

def add_credential(
    user_id: int,
    website: str,
    username: str,
    password_enc: str,
    notes_enc: str = "",
    category: str = "General",
) -> int:
    with get_connection() as conn:
        cur = conn.execute(
            """INSERT INTO credentials
               (user_id, website, username, password_enc, notes_enc, category)
               VALUES (?, ?, ?, ?, ?, ?)""",
            (user_id, website, username, password_enc, notes_enc, category),
        )
        cred_id = cur.lastrowid
    log_event(user_id, "CREDENTIAL_ADDED", f"website={website}")
    return cred_id


def get_credentials(user_id: int, search: str = "") -> list[dict]:
    """Return all credentials for user, optionally filtered by search term."""
    with get_connection() as conn:
        if search:
            rows = conn.execute(
                """SELECT * FROM credentials
                   WHERE user_id = ?
                     AND (LOWER(website) LIKE ? OR LOWER(username) LIKE ?)
                   ORDER BY website""",
                (user_id, f"%{search.lower()}%", f"%{search.lower()}%"),
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT * FROM credentials WHERE user_id = ? ORDER BY website",
                (user_id,),
            ).fetchall()
    return [dict(r) for r in rows]


def get_credential_by_id(cred_id: int, user_id: int) -> Optional[dict]:
    with get_connection() as conn:
        row = conn.execute(
            "SELECT * FROM credentials WHERE id = ? AND user_id = ?",
            (cred_id, user_id),
        ).fetchone()
    return dict(row) if row else None


def update_credential(
    cred_id: int,
    user_id: int,
    website: str,
    username: str,
    password_enc: str,
    notes_enc: str = "",
    category: str = "General",
) -> bool:
    now = datetime.now(timezone.utc).isoformat()
    with get_connection() as conn:
        cur = conn.execute(
            """UPDATE credentials
               SET website=?, username=?, password_enc=?,
                   notes_enc=?, category=?, updated_at=?
               WHERE id=? AND user_id=?""",
            (website, username, password_enc, notes_enc, category, now, cred_id, user_id),
        )
    if cur.rowcount:
        log_event(user_id, "CREDENTIAL_UPDATED", f"id={cred_id} website={website}")
        return True
    return False


def delete_credential(cred_id: int, user_id: int) -> bool:
    with get_connection() as conn:
        cur = conn.execute(
            "DELETE FROM credentials WHERE id=? AND user_id=?",
            (cred_id, user_id),
        )
    if cur.rowcount:
        log_event(user_id, "CREDENTIAL_DELETED", f"id={cred_id}")
        return True
    return False


# ─── Audit Log ────────────────────────────────────────────────────────────────

def log_event(
    user_id: Optional[int],
    event: str,
    detail: str = "",
    ip_hint: str = "",
) -> None:
    """Write a security event to the immutable audit log."""
    try:
        with get_connection() as conn:
            conn.execute(
                "INSERT INTO audit_log (user_id, event, detail, ip_hint) VALUES (?,?,?,?)",
                (user_id, event, detail, ip_hint),
            )
    except Exception as exc:
        logger.error("Audit log write failed: %s", exc)


def get_audit_log(user_id: int, limit: int = 50) -> list[dict]:
    with get_connection() as conn:
        rows = conn.execute(
            "SELECT * FROM audit_log WHERE user_id=? ORDER BY ts DESC LIMIT ?",
            (user_id, limit),
        ).fetchall()
    return [dict(r) for r in rows]
