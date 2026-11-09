
import pandas as pd


SEVERITY_RANK = {
    "Low": 1,
    "Medium": 2,
    "High": 3,
    "Critical": 4
}


def correlate_alerts(alerts, window_minutes=15):
    """
    Group related alerts into incidents using shared IP addresses
    or usernames within a configurable time window.
    """

    if alerts.empty:
        return pd.DataFrame(), alerts.copy()

    data = alerts.copy().reset_index(drop=True)
    data["timestamp"] = pd.to_datetime(
        data["timestamp"], utc=True
    )

    parent = list(range(len(data)))

    def find(x):
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    def union(a, b):
        root_a = find(a)
        root_b = find(b)
        if root_a != root_b:
            parent[root_b] = root_a

    for i in range(len(data)):
        for j in range(i + 1, len(data)):
            time_difference = abs(
                (data.loc[i, "timestamp"] -
                 data.loc[j, "timestamp"]).total_seconds()
            )

            if time_difference > window_minutes * 60:
                continue

            ip_a = str(data.loc[i, "source_ip"]).strip()
            ip_b = str(data.loc[j, "source_ip"]).strip()

            user_a = str(data.loc[i, "username"]).strip().lower()
            user_b = str(data.loc[j, "username"]).strip().lower()

            same_ip = (
                ip_a not in ("", "unknown", "none", "nan")
                and ip_a == ip_b
            )

            same_user = (
                user_a not in ("", "unknown", "none", "nan")
                and user_a == user_b
            )

            if same_ip or same_user:
                union(i, j)

    groups = {}

    for i in range(len(data)):
        root = find(i)
        groups.setdefault(root, []).append(i)

    incidents = []
    incident_ids = {}

    for number, indexes in enumerate(groups.values(), start=1):
        group = data.iloc[indexes]

        highest_severity = max(
            group["severity"],
            key=lambda x: SEVERITY_RANK.get(x, 0)
        )

        incident_id = f"INC-{number:04d}"

        incidents.append({
            "incident_id": incident_id,
            "title": " / ".join(
                group["rule"].dropna().unique()[:2]
            ),
            "severity": highest_severity,
            "alert_count": len(group),
            "first_seen": group["timestamp"].min(),
            "last_seen": group["timestamp"].max(),
            "source_ips": ", ".join(
                group["source_ip"].dropna().unique()
            ),
            "affected_users": ", ".join(
                group["username"].dropna().unique()
            ),
            "status": "Open"
        })

        for index in indexes:
            incident_ids[index] = incident_id

    data["incident_id"] = [
        incident_ids[i] for i in range(len(data))
    ]

    return pd.DataFrame(incidents), data
