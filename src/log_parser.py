from pathlib import Path
import pandas as pd

REQUIRED_COLUMNS = {"timestamp", "event_type", "username", "source_ip", "message"}

def load_logs(source):
    """Load CSV logs and normalize timestamps and event fields."""
    df = pd.read_csv(source)
    missing = REQUIRED_COLUMNS - set(df.columns)
    if missing:
        raise ValueError("Missing required column(s): " + ", ".join(sorted(missing)))

    df = df.copy()
    df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce", utc=True)
    if df["timestamp"].isna().any():
        raise ValueError("One or more timestamps could not be parsed. Use ISO 8601, e.g. 2026-11-08T08:30:00Z.")

    for column in ["event_type", "username", "source_ip", "message"]:
        df[column] = df[column].fillna("").astype(str).str.strip()

    df["event_type"] = df["event_type"].str.lower()
    df = df.sort_values("timestamp").reset_index(drop=True)
    return df
