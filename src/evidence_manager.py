
import hashlib
import sqlite3
import uuid
from datetime import datetime, timezone
from pathlib import Path

import pandas as pd


# --------------------------------------------------
# CONFIGURATION
# --------------------------------------------------

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = PROJECT_ROOT / "data"
EVIDENCE_DIR = DATA_DIR / "evidence"
DB_PATH = DATA_DIR / "sentinel_siem.db"

MAX_FILE_SIZE = 25 * 1024 * 1024  # 25 MB


# --------------------------------------------------
# DATABASE CONNECTION
# --------------------------------------------------

def get_connection():
    DATA_DIR.mkdir(parents=True, exist_ok=True)

    connection = sqlite3.connect(DB_PATH)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")

    return connection


def current_time():
    return datetime.now(timezone.utc).isoformat()


def calculate_sha256(file_bytes):
    return hashlib.sha256(file_bytes).hexdigest()


# --------------------------------------------------
# INITIALISE EVIDENCE DATABASE
# --------------------------------------------------

def initialise_evidence_database():
    EVIDENCE_DIR.mkdir(parents=True, exist_ok=True)

    with get_connection() as connection:
        connection.execute("""
            CREATE TABLE IF NOT EXISTS evidence (
                evidence_id TEXT PRIMARY KEY,
                incident_ref TEXT NOT NULL,
                original_filename TEXT NOT NULL,
                stored_filename TEXT NOT NULL,
                stored_path TEXT NOT NULL,
                sha256 TEXT NOT NULL,
                file_size INTEGER NOT NULL,
                content_type TEXT,
                description TEXT,
                uploaded_by TEXT NOT NULL,
                uploaded_at TEXT NOT NULL,
                FOREIGN KEY (incident_ref)
                    REFERENCES incidents (incident_ref)
            )
        """)


# --------------------------------------------------
# AUDIT TRAIL
# --------------------------------------------------

def record_evidence_audit(
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
        analyst or "System",
        action,
        details,
        current_time()
    ))


# --------------------------------------------------
# UPLOAD EVIDENCE
# --------------------------------------------------

def add_evidence(
    incident_ref,
    original_filename,
    file_bytes,
    uploaded_by,
    description="",
    content_type="application/octet-stream"
):
    initialise_evidence_database()

    if not file_bytes:
        raise ValueError("The uploaded file is empty.")

    if len(file_bytes) > MAX_FILE_SIZE:
        raise ValueError("File exceeds the 25 MB upload limit.")

    if not original_filename:
        raise ValueError("A filename is required.")

    if not uploaded_by.strip():
        raise ValueError("Please provide the analyst name.")

    # Confirm that the incident exists.
    with get_connection() as connection:
        incident = connection.execute("""
            SELECT incident_ref
            FROM incidents
            WHERE incident_ref = ?
        """, (incident_ref,)).fetchone()

        if not incident:
            raise ValueError("The selected incident does not exist.")

    evidence_id = uuid.uuid4().hex

    # Keep only the file extension; never use the supplied
    # filename as a storage path.
    extension = Path(original_filename).suffix.lower()

    if len(extension) > 15:
        extension = ""

    stored_filename = f"{evidence_id}{extension}"
    stored_path = EVIDENCE_DIR / stored_filename

    file_hash = calculate_sha256(file_bytes)

    try:
        # Save the evidence file.
        stored_path.write_bytes(file_bytes)

        with get_connection() as connection:
            connection.execute("""
                INSERT INTO evidence (
                    evidence_id,
                    incident_ref,
                    original_filename,
                    stored_filename,
                    stored_path,
                    sha256,
                    file_size,
                    content_type,
                    description,
                    uploaded_by,
                    uploaded_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                evidence_id,
                incident_ref,
                Path(original_filename).name,
                stored_filename,
                str(stored_path),
                file_hash,
                len(file_bytes),
                content_type,
                description.strip(),
                uploaded_by.strip(),
                current_time()
            ))

            record_evidence_audit(
                connection,
                incident_ref,
                uploaded_by,
                "EVIDENCE_UPLOADED",
                (
                    f"Uploaded {Path(original_filename).name}. "
                    f"SHA-256: {file_hash}"
                )
            )

    except Exception:
        if stored_path.exists():
            stored_path.unlink()
        raise

    return {
        "evidence_id": evidence_id,
        "filename": Path(original_filename).name,
        "sha256": file_hash
    }


# --------------------------------------------------
# RETRIEVE EVIDENCE
# --------------------------------------------------

def get_evidence(incident_ref):
    initialise_evidence_database()

    with get_connection() as connection:
        rows = connection.execute("""
            SELECT
                evidence_id,
                original_filename,
                sha256,
                file_size,
                content_type,
                description,
                uploaded_by,
                uploaded_at
            FROM evidence
            WHERE incident_ref = ?
            ORDER BY uploaded_at DESC
        """, (incident_ref,)).fetchall()

    return pd.DataFrame([dict(row) for row in rows])


def get_evidence_file(evidence_id):
    initialise_evidence_database()

    with get_connection() as connection:
        row = connection.execute("""
            SELECT
                original_filename,
                stored_path,
                content_type
            FROM evidence
            WHERE evidence_id = ?
        """, (evidence_id,)).fetchone()

    if not row:
        raise ValueError("Evidence record not found.")

    file_path = Path(row["stored_path"]).resolve()

    # Ensure the stored path remains inside the evidence directory.
    if not file_path.is_relative_to(EVIDENCE_DIR.resolve()):
        raise ValueError("Invalid evidence storage path.")

    if not file_path.is_file():
        raise FileNotFoundError("The evidence file is missing.")

    return (
        file_path.read_bytes(),
        row["original_filename"],
        row["content_type"] or "application/octet-stream"
    )


# --------------------------------------------------
# VERIFY EVIDENCE INTEGRITY
# --------------------------------------------------

def verify_evidence(evidence_id, analyst="Analyst"):
    initialise_evidence_database()

    with get_connection() as connection:
        row = connection.execute("""
            SELECT
                incident_ref,
                original_filename,
                stored_path,
                sha256
            FROM evidence
            WHERE evidence_id = ?
        """, (evidence_id,)).fetchone()

        if not row:
            raise ValueError("Evidence record not found.")

        file_path = Path(row["stored_path"]).resolve()

        if not file_path.is_relative_to(EVIDENCE_DIR.resolve()):
            raise ValueError("Invalid evidence storage path.")

        if not file_path.is_file():
            record_evidence_audit(
                connection,
                row["incident_ref"],
                analyst,
                "EVIDENCE_INTEGRITY_FAILED",
                f"Evidence file is missing: {row['original_filename']}"
            )

            return {
                "valid": False,
                "expected_hash": row["sha256"],
                "actual_hash": None,
                "message": "Evidence file is missing."
            }

        actual_hash = calculate_sha256(file_path.read_bytes())
        expected_hash = row["sha256"]

        valid = actual_hash == expected_hash

        action = (
            "EVIDENCE_INTEGRITY_VERIFIED"
            if valid
            else "EVIDENCE_INTEGRITY_FAILED"
        )

        details = (
            f"{row['original_filename']}: "
            f"{'Hash matched' if valid else 'Hash mismatch'}. "
            f"Expected: {expected_hash}. "
            f"Actual: {actual_hash}."
        )

        record_evidence_audit(
            connection,
            row["incident_ref"],
            analyst,
            action,
            details
        )

    return {
        "valid": valid,
        "expected_hash": expected_hash,
        "actual_hash": actual_hash,
        "message": (
            "Integrity check passed. The file matches its recorded hash."
            if valid
            else "Integrity check failed. The file differs from its recorded hash."
        )
    }
