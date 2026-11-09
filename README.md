# SentinelSIEM

A beginner-friendly Python SIEM log analyzer with a Streamlit dashboard.

## Features
- CSV log ingestion and normalization
- Repeated failed-login detection
- Successful login after repeated failures
- Privileged account activity detection
- Severity labels and investigation recommendations
- Dashboard charts and CSV exports

## Setup (Windows PowerShell)

```powershell
py -3 -m venv .venv
.venv\\Scripts\\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
streamlit run app.py
```

If PowerShell blocks activation, run:
```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.venv\\Scripts\\Activate.ps1
```

## Setup (Linux / Kali / WSL)

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
pip install -r requirements.txt
streamlit run app.py
```

## CSV format

Required columns:

`timestamp,event_type,username,source_ip,message`

Supported initial event types:
- `login_failed`
- `login_success`
- `privilege_escalation`

Timestamps should be ISO 8601, preferably UTC, e.g. `2026-11-08T08:30:00Z`.

## Run tests

```bash
pytest -q
```

## Important limitations
This is a learning/portfolio prototype, not a production SIEM. The sample IP ranges are documentation-only reserved ranges. Detection rules are heuristic and can produce false positives. Do not treat an alert as proof of compromise.
