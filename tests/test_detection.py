import pandas as pd
from src.detection_engine import analyze_logs

def test_brute_force_and_success_after_failures():
    rows = []
    base = pd.Timestamp("2026-11-08T08:00:00Z")
    for i in range(5):
        rows.append({
            "timestamp": base + pd.Timedelta(seconds=30*i),
            "event_type": "login_failed",
            "username": "tester",
            "source_ip": "198.51.100.77",
            "message": "Invalid password"
        })
    rows.append({
        "timestamp": base + pd.Timedelta(minutes=3),
        "event_type": "login_success",
        "username": "tester",
        "source_ip": "198.51.100.77",
        "message": "Login successful"
    })
    alerts = analyze_logs(pd.DataFrame(rows))
    assert "Repeated failed logins" in set(alerts["rule"])
    assert "Successful login after repeated failures" in set(alerts["rule"])
