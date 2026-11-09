
import pandas as pd


def analyze_logs(logs, failed_threshold=5, window_minutes=5):
    """
    Analyze normalized logs and generate explainable security alerts.
    Alerts are investigation leads, not proof of compromise.
    """

    alerts = []

    def add_alert(event, rule, severity, description, recommendation):
        alerts.append({
            "timestamp": event["timestamp"],
            "event_id": event.get("event_id", "N/A"),
            "rule": rule,
            "severity": severity,
            "source_ip": event.get("source_ip", "Unknown"),
            "username": event.get("username", "Unknown"),
            "event_count": 1,
            "description": description,
            "recommendation": recommendation
        })

    # Normalize event IDs where available.
    event_ids = (
        pd.to_numeric(logs["event_id"], errors="coerce")
        if "event_id" in logs.columns
        else pd.Series(index=logs.index, dtype="float64")
    )

    failed = logs[logs["event_type"] == "login_failed"].copy()

    # RULE 1: Brute-force detection.
    for source_ip, group in failed.groupby("source_ip"):
        group = group.sort_values("timestamp")
        times = group["timestamp"].tolist()

        for index, end_time in enumerate(times):
            start_time = end_time - pd.Timedelta(minutes=window_minutes)

            recent = [
                t for t in times[:index + 1]
                if start_time <= t <= end_time
            ]

            if len(recent) >= failed_threshold:
                event = group.iloc[index].to_dict()

                add_alert(
                    event,
                    "Possible brute-force attack",
                    "High",
                    f"{len(recent)} failed logins from {source_ip} "
                    f"within {window_minutes} minutes.",
                    "Investigate the source IP, affected accounts and "
                    "authentication history."
                )
                break

    # RULE 2: Successful login after repeated failures.
    successes = logs[logs["event_type"] == "login_success"]

    for _, success in successes.iterrows():
        start = success["timestamp"] - pd.Timedelta(
            minutes=window_minutes
        )

        prior = failed[
            (failed["source_ip"] == success["source_ip"]) &
            (failed["timestamp"] >= start) &
            (failed["timestamp"] <= success["timestamp"])
        ]

        if len(prior) >= failed_threshold:
            add_alert(
                success.to_dict(),
                "Successful login after repeated failures",
                "Critical",
                f"Login for {success['username']} succeeded after "
                f"{len(prior)} failed attempts from the same IP.",
                "Verify the login with the account owner and investigate "
                "the source IP and account activity."
            )

    # RULE 3: Windows special privileges assigned (4672).
    for index, event in logs[event_ids == 4672].iterrows():
        add_alert(
            event.to_dict(),
            "Special privileges assigned",
            "Medium",
            "Windows recorded special privileges assigned to a new logon.",
            "Verify that the account and privileges are authorized. "
            "This event can occur during legitimate administrative activity."
        )

    # RULE 4: Windows account created (4720).
    for index, event in logs[event_ids == 4720].iterrows():
        add_alert(
            event.to_dict(),
            "Windows account created",
            "Medium",
            f"An account creation event was recorded for "
            f"{event['username']}.",
            "Verify that the account creation was approved and identify "
            "the administrator responsible."
        )

    # RULE 5: Windows account locked out (4740).
    for index, event in logs[event_ids == 4740].iterrows():
        add_alert(
            event.to_dict(),
            "Windows account lockout",
            "Medium",
            f"Windows recorded a lockout involving {event['username']}.",
            "Review authentication failures and determine whether "
            "the lockout was caused by legitimate or suspicious activity."
        )

    # RULE 6: Security-enabled group membership changed.
    for index, event in logs[event_ids.isin([4728, 4732])].iterrows():
        add_alert(
            event.to_dict(),
            "Security group membership changed",
            "High",
            f"Windows recorded a security group membership change "
            f"(Event ID {int(event_ids.loc[index])}).",
            "Review the affected group and member. Confirm that the "
            "change was authorized."
        )

    columns = [
        "timestamp", "event_id", "rule", "severity",
        "source_ip", "username", "event_count",
        "description", "recommendation"
    ]

    if not alerts:
        return pd.DataFrame(columns=columns)

    result = pd.DataFrame(alerts)

    result = result.drop_duplicates(
        subset=["timestamp", "event_id", "rule", "source_ip", "username"]
    )

    return result.sort_values(
        "timestamp", ascending=False
    ).reset_index(drop=True)
