"""
SentinelSIEM authentication and role management.

Passwords are stored as PBKDF2-HMAC-SHA256 hashes with unique random salts.
This module shares the existing SQLite database and does not modify incident,
evidence, note, or audit records.
"""
import hashlib
import hmac
import secrets
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = PROJECT_ROOT / "data"
DB_PATH = DATA_DIR / "sentinel_siem.db"

ROLES = ("Administrator", "SOC Analyst", "Read-Only Viewer")
ITERATIONS = 600_000
MIN_PASSWORD_LENGTH = 12


def _now():
    return datetime.now(timezone.utc).isoformat()


def _connection():
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH, timeout=15)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def initialise_auth_database():
    with _connection() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS app_users (
                user_id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL COLLATE NOCASE UNIQUE,
                display_name TEXT NOT NULL,
                password_hash TEXT NOT NULL,
                password_salt TEXT NOT NULL,
                role TEXT NOT NULL CHECK (
                    role IN ('Administrator', 'SOC Analyst', 'Read-Only Viewer')
                ),
                is_active INTEGER NOT NULL DEFAULT 1,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                last_login TEXT
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS auth_audit (
                audit_id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL,
                action TEXT NOT NULL,
                details TEXT,
                created_at TEXT NOT NULL
            )
        """)


def _hash_password(password, salt_hex=None):
    salt = bytes.fromhex(salt_hex) if salt_hex else secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt, ITERATIONS
    )
    return digest.hex(), salt.hex()


def _validate_password(password):
    if len(password) < MIN_PASSWORD_LENGTH:
        raise ValueError("Password must be at least 12 characters long.")
    if password.strip() != password:
        raise ValueError("Password cannot begin or end with spaces.")


def _audit(conn, username, action, details=""):
    conn.execute(
        "INSERT INTO auth_audit (username, action, details, created_at) VALUES (?, ?, ?, ?)",
        (username, action, details, _now()),
    )


def user_count():
    initialise_auth_database()
    with _connection() as conn:
        return conn.execute("SELECT COUNT(*) FROM app_users").fetchone()[0]


def create_first_admin(username, display_name, password):
    initialise_auth_database()
    username = username.strip()
    display_name = display_name.strip()
    if not username or not display_name:
        raise ValueError("Username and display name are required.")
    _validate_password(password)
    password_hash, salt = _hash_password(password)

    with _connection() as conn:
        count = conn.execute("SELECT COUNT(*) FROM app_users").fetchone()[0]
        if count:
            raise ValueError("Initial administrator setup has already been completed.")
        conn.execute("""
            INSERT INTO app_users
            (username, display_name, password_hash, password_salt, role,
             is_active, created_at, updated_at)
            VALUES (?, ?, ?, ?, 'Administrator', 1, ?, ?)
        """, (username, display_name, password_hash, salt, _now(), _now()))
        _audit(conn, username, "INITIAL_ADMIN_CREATED", "Initial administrator account created.")


def authenticate_user(username, password):
    initialise_auth_database()
    username = username.strip()
    with _connection() as conn:
        row = conn.execute(
            "SELECT * FROM app_users WHERE username = ? COLLATE NOCASE",
            (username,),
        ).fetchone()

        # Perform a dummy PBKDF2 operation for unknown usernames too.
        if not row:
            _hash_password(password, "00112233445566778899aabbccddeeff")
            return None
        if not row["is_active"]:
            return None

        digest, _ = _hash_password(password, row["password_salt"])
        if not hmac.compare_digest(digest, row["password_hash"]):
            _audit(conn, username, "LOGIN_FAILED", "Invalid password.")
            return None

        conn.execute(
            "UPDATE app_users SET last_login = ?, updated_at = ? WHERE user_id = ?",
            (_now(), _now(), row["user_id"]),
        )
        _audit(conn, username, "LOGIN_SUCCESS", "User signed in.")
        return {
            "user_id": row["user_id"],
            "username": row["username"],
            "display_name": row["display_name"],
            "role": row["role"],
        }


def get_user(username):
    initialise_auth_database()
    with _connection() as conn:
        row = conn.execute("""
            SELECT user_id, username, display_name, role, is_active,
                   created_at, updated_at, last_login
            FROM app_users WHERE username = ? COLLATE NOCASE
        """, (username,)).fetchone()
    return dict(row) if row else None


def list_users():
    initialise_auth_database()
    with _connection() as conn:
        rows = conn.execute("""
            SELECT user_id, username, display_name, role, is_active,
                   created_at, last_login
            FROM app_users ORDER BY username COLLATE NOCASE
        """).fetchall()
    return [dict(row) for row in rows]



def _require_admin(conn, actor):
    row = conn.execute("""
        SELECT role, is_active FROM app_users
        WHERE username = ? COLLATE NOCASE
    """, (actor,)).fetchone()
    if not row or not row["is_active"] or row["role"] != "Administrator":
        raise PermissionError("Administrator privileges are required.")


def create_user(actor, username, display_name, password, role):
    initialise_auth_database()
    if role not in ROLES:
        raise ValueError("Select a valid role.")
    username, display_name = username.strip(), display_name.strip()
    if not username or not display_name:
        raise ValueError("Username and display name are required.")
    if len(username) < 3:
        raise ValueError("Username must contain at least 3 characters.")
    _validate_password(password)
    password_hash, salt = _hash_password(password)

    with _connection() as conn:
        _require_admin(conn, actor)
        conn.execute("""
            INSERT INTO app_users
            (username, display_name, password_hash, password_salt, role,
             is_active, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, 1, ?, ?)
        """, (username, display_name, password_hash, salt, role, _now(), _now()))
        _audit(conn, actor, "USER_CREATED", f"Created {username} with role {role}.")


def update_user_role(actor, username, new_role):
    if new_role not in ROLES:
        raise ValueError("Select a valid role.")
    with _connection() as conn:
        _require_admin(conn, actor)
        row = conn.execute(
            "SELECT role, is_active FROM app_users WHERE username = ? COLLATE NOCASE",
            (username,),
        ).fetchone()
        if not row:
            raise ValueError("User not found.")
        if row["role"] == "Administrator" and row["is_active"] and new_role != "Administrator":
            admins = conn.execute("""
                SELECT COUNT(*) FROM app_users
                WHERE role = 'Administrator' AND is_active = 1
            """).fetchone()[0]
            if admins <= 1:
                raise ValueError("You cannot remove the last active administrator.")
        conn.execute(
            "UPDATE app_users SET role = ?, updated_at = ? WHERE username = ? COLLATE NOCASE",
            (new_role, _now(), username),
        )
        _audit(conn, actor, "USER_ROLE_CHANGED", f"Changed {username} role to {new_role}.")


def set_user_active(actor, username, active):
    with _connection() as conn:
        _require_admin(conn, actor)
        row = conn.execute(
            "SELECT role, is_active FROM app_users WHERE username = ? COLLATE NOCASE",
            (username,),
        ).fetchone()
        if not row:
            raise ValueError("User not found.")
        if row["role"] == "Administrator" and row["is_active"] and not active:
            admins = conn.execute("""
                SELECT COUNT(*) FROM app_users
                WHERE role = 'Administrator' AND is_active = 1
            """).fetchone()[0]
            if admins <= 1:
                raise ValueError("You cannot deactivate the last active administrator.")
        conn.execute(
            "UPDATE app_users SET is_active = ?, updated_at = ? WHERE username = ? COLLATE NOCASE",
            (1 if active else 0, _now(), username),
        )
        _audit(conn, actor, "USER_ACTIVATED" if active else "USER_DEACTIVATED", username)


def reset_user_password(actor, username, new_password):
    _validate_password(new_password)
    password_hash, salt = _hash_password(new_password)
    with _connection() as conn:
        _require_admin(conn, actor)
        cursor = conn.execute("""
            UPDATE app_users
            SET password_hash = ?, password_salt = ?, updated_at = ?
            WHERE username = ? COLLATE NOCASE
        """, (password_hash, salt, _now(), username))
        if cursor.rowcount != 1:
            raise ValueError("User not found.")
        _audit(conn, actor, "USER_PASSWORD_RESET", f"Password reset for {username}.")


def get_auth_audit(limit=200):
    initialise_auth_database()
    with _connection() as conn:
        rows = conn.execute("""
            SELECT username, action, details, created_at
            FROM auth_audit ORDER BY audit_id DESC LIMIT ?
        """, (int(limit),)).fetchall()
    return [dict(row) for row in rows]
