import hashlib
import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

import pandas as pd


# --------------------------------------------------
# DATABASE CONFIGURATION
# --------------------------------------------------

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = PROJECT_ROOT / "data"
DB_PATH = DATA_DIR / "sentinel_siem.db"

VALID_STATUSES = [
    "Open",
    "Investigating",
    "Resolved",
    "Closed"
]


# --------------------------------------------------
# DATABASE CONNECTION
# --------------------------------------------------

def get_connection():
    DATA_DIR.mkdir(parents=True, exist_ok=True)

    connection = sqlite3.connect(DB_PATH)
    connection.row_factory = sqlite3.Row

    return connection


def current_time():
    return datetime.now(timezone.utc).isoformat()


def initialise_database():
    with get_connection() as connection:

        connection.execute("""
            CREATE TABLE IF NOT EXISTS incidents (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                incident_ref TEXT UNIQUE,
                fingerprint TEXT UNIQUE NOT NULL,
                title TEXT,
                severity TEXT,
                alert_count INTEGER DEFAULT 0,
                first_seen TEXT,
                last_seen TEXT,
                source_ips TEXT,
                affected_users TEXT,
                status TEXT DEFAULT 'Open',
                alerts_json TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
        """)

        connection.execute("""
            CREATE TABLE IF NOT EXISTS investigation_notes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                incident_ref TEXT NOT NULL,
                analyst TEXT NOT NULL,
                note TEXT NOT NULL,
                created_at TEXT NOT NULL,
                FOREIGN KEY (incident_ref)
                    REFERENCES incidents (incident_ref)
            )
        """)

        connection.execute("""
            CREATE TABLE IF NOT EXISTS incident_audit (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                incident_ref TEXT NOT NULL,
                analyst TEXT NOT NULL,
                action TEXT NOT NULL,
                details TEXT,
                created_at TEXT NOT NULL,
                FOREIGN KEY (incident_ref)
                    REFERENCES incidents (incident_ref)
            )
        """)


# --------------------------------------------------
# AUDIT LOGGING
# --------------------------------------------------

def record_audit_event(
    connection,
    incident_ref,
    analyst,
    action,
    details
):
    connection.execute("""
        INSERT INTO incident_audit (
            incident_ref,
            analyst,
            action,
            details,
            created_at
        )
        VALUES (?, ?, ?, ?, ?)
    """, (
        incident_ref,
        analyst.strip() or "System",
        action,
        details,
        current_time()
    ))


def get_incident_audit(incident_ref):
    initialise_database()

    with get_connection() as connection:

        rows = connection.execute("""
            SELECT
                analyst,
                action,
                details,
                created_at
            FROM incident_audit
            WHERE incident_ref = ?
            ORDER BY created_at DESC, id DESC
        """, (incident_ref,)).fetchall()

    return pd.DataFrame([dict(row) for row in rows])


# --------------------------------------------------
# ALERT FINGERPRINTING
# --------------------------------------------------

def make_alert_key(row):
    fields = [
        str(row.get("timestamp", "")),
        str(row.get("event_id", "")),
        str(row.get("rule", "")),
        str(row.get("severity", "")),
        str(row.get("source_ip", "")),
        str(row.get("username", "")),
        str(row.get("description", ""))
    ]

    return "|".join(fields)


def make_fingerprint(group):
    alert_keys = sorted(
        make_alert_key(row)
        for row in group.to_dict(orient="records")
    )

    raw_value = json.dumps(alert_keys, sort_keys=True)

    return hashlib.sha256(
        raw_value.encode("utf-8")
    ).hexdigest()


def clean_value(value):
    if pd.isna(value):
        return None

    if isinstance(value, (pd.Timestamp, datetime)):
        return value.isoformat()

    return value


# --------------------------------------------------
# SAVE AND UPDATE INCIDENTS
# --------------------------------------------------

def save_incidents(incidents, alerts):
    """
    Save correlated incidents in SQLite.

    Returns a dictionary mapping temporary correlation IDs
    to permanent incident references.
    """

    initialise_database()

    persistent_ids = {}

    if incidents.empty:
        return persistent_ids

    with get_connection() as connection:

        for _, incident in incidents.iterrows():

            temporary_id = str(incident["incident_id"])

            related = alerts[
                alerts["incident_id"].astype(str) == temporary_id
            ].copy()

            fingerprint = make_fingerprint(related)

            alert_records = [
                {
                    key: clean_value(value)
                    for key, value in record.items()
                }
                for record in related.to_dict(orient="records")
            ]

            alerts_json = json.dumps(
                alert_records,
                default=str
            )

            values = (
                str(incident.get("title", "Security incident")),
                str(incident.get("severity", "Low")),
                int(incident.get("alert_count", len(related))),
                str(incident.get("first_seen", "")),
                str(incident.get("last_seen", "")),
                str(incident.get("source_ips", "")),
                str(incident.get("affected_users", "")),
                alerts_json
            )

            existing = connection.execute("""
                SELECT incident_ref
                FROM incidents
                WHERE fingerprint = ?
            """, (fingerprint,)).fetchone()

            if existing:

                incident_ref = existing["incident_ref"]

                connection.execute("""
                    UPDATE incidents
                    SET
                        title = ?,
                        severity = ?,
                        alert_count = ?,
                        first_seen = ?,
                        last_seen = ?,
                        source_ips = ?,
                        affected_users = ?,
                        alerts_json = ?,
                        updated_at = ?
                    WHERE fingerprint = ?
                """, (
                    *values,
                    current_time(),
                    fingerprint
                ))

            else:

                cursor = connection.execute("""
                    INSERT INTO incidents (
                        fingerprint,
                        title,
                        severity,
                        alert_count,
                        first_seen,
                        last_seen,
                        source_ips,
                        affected_users,
                        alerts_json,
                        created_at,
                        updated_at
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    fingerprint,
                    *values,
                    current_time(),
                    current_time()
                ))

                incident_ref = (
                    f"INC-{cursor.lastrowid:06d}"
                )

                connection.execute("""
                    UPDATE incidents
                    SET incident_ref = ?
                    WHERE id = ?
                """, (
                    incident_ref,
                    cursor.lastrowid
                ))

                record_audit_event(
                    connection,
                    incident_ref,
                    "System",
                    "INCIDENT_CREATED",
                    "Incident automatically created from correlated security alerts."
                )

            persistent_ids[temporary_id] = incident_ref

    return persistent_ids


# --------------------------------------------------
# RETRIEVE INCIDENTS
# --------------------------------------------------

def get_incidents():
    initialise_database()

    with get_connection() as connection:

        rows = connection.execute("""
            SELECT
                incident_ref AS incident_id,
                title,
                severity,
                alert_count,
                first_seen,
                last_seen,
                source_ips,
                affected_users,
                status,
                created_at,
                updated_at
            FROM incidents
            ORDER BY
                CASE severity
                    WHEN 'Critical' THEN 1
                    WHEN 'High' THEN 2
                    WHEN 'Medium' THEN 3
                    ELSE 4
                END,
                updated_at DESC
        """).fetchall()

    return pd.DataFrame([
        dict(row) for row in rows
    ])


def get_incident_alerts(incident_ref):
    initialise_database()

    with get_connection() as connection:

        row = connection.execute("""
            SELECT alerts_json
            FROM incidents
            WHERE incident_ref = ?
        """, (incident_ref,)).fetchone()

    if not row or not row["alerts_json"]:
        return pd.DataFrame()

    return pd.DataFrame(
        json.loads(row["alerts_json"])
    )


# --------------------------------------------------
# UPDATE INCIDENT STATUS
# --------------------------------------------------

def update_incident_status(
    incident_ref,
    new_status,
    analyst="Analyst"
):
    if new_status not in VALID_STATUSES:
        raise ValueError("Invalid incident status.")

    initialise_database()

    with get_connection() as connection:

        existing = connection.execute("""
            SELECT status
            FROM incidents
            WHERE incident_ref = ?
        """, (incident_ref,)).fetchone()

        if not existing:
            raise ValueError("Incident not found.")

        old_status = existing["status"]

        if old_status == new_status:
            return

        connection.execute("""
            UPDATE incidents
            SET
                status = ?,
                updated_at = ?
            WHERE incident_ref = ?
        """, (
            new_status,
            current_time(),
            incident_ref
        ))

        record_audit_event(
            connection,
            incident_ref,
            analyst,
            "STATUS_CHANGED",
            f"Status changed from {old_status} to {new_status}."
        )


# --------------------------------------------------
# INVESTIGATION NOTES
# --------------------------------------------------

def add_investigation_note(
    incident_ref,
    analyst,
    note
):
    note = note.strip()
    analyst = analyst.strip() or "Analyst"

    if not note:
        raise ValueError(
            "Investigation note cannot be empty."
        )

    initialise_database()

    with get_connection() as connection:

        existing = connection.execute("""
            SELECT incident_ref
            FROM incidents
            WHERE incident_ref = ?
        """, (incident_ref,)).fetchone()

        if not existing:
            raise ValueError("Incident not found.")

        connection.execute("""
            INSERT INTO investigation_notes (
                incident_ref,
                analyst,
                note,
                created_at
            )
            VALUES (?, ?, ?, ?)
        """, (
            incident_ref,
            analyst,
            note,
            current_time()
        ))

        connection.execute("""
            UPDATE incidents
            SET updated_at = ?
            WHERE incident_ref = ?
        """, (
            current_time(),
            incident_ref
        ))

        record_audit_event(
            connection,
            incident_ref,
            analyst,
            "INVESTIGATION_NOTE_ADDED",
            "An investigation note was added."
        )


def get_investigation_notes(incident_ref):
    initialise_database()

    with get_connection() as connection:

        rows = connection.execute("""
            SELECT
                analyst,
                note,
                created_at
            FROM investigation_notes
            WHERE incident_ref = ?
            ORDER BY created_at DESC, id DESC
        """, (incident_ref,)).fetchall()

    return pd.DataFrame([
        dict(row) for row in rows
    ])