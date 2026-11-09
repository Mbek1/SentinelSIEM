import sys
from pathlib import Path

import pandas as pd
import plotly.express as px
import streamlit as st

# --------------------------------------------------
# PROJECT PATH AND IMPORTS
# --------------------------------------------------

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

from src.log_parser import load_logs
from src.detection_engine import analyze_logs
from src.incident_manager import correlate_alerts

from src.incident_store import (
    initialise_database,
    save_incidents,
    get_incidents,
    update_incident_status,
    add_investigation_note,
    get_investigation_notes,
    get_incident_alerts,
    get_incident_audit,
)

from src.evidence_manager import (
    initialise_evidence_database,
    add_evidence,
    get_evidence,
    get_evidence_file,
    verify_evidence,
)

from src.report_generator import generate_incident_report

from src.auth_manager import (
    initialise_auth_database,
    user_count,
    create_first_admin,
    authenticate_user,
    get_user,
    list_users,
    create_user,
    update_user_role,
    set_user_active,
    reset_user_password,
    get_auth_audit,
    ROLES,
)


# --------------------------------------------------
# PAGE CONFIGURATION AND DATABASE INITIALISATION
# --------------------------------------------------

st.set_page_config(
    page_title="SentinelSIEM | SOC Dashboard",
    page_icon="🛡️",
    layout="wide",
)

initialise_database()
initialise_evidence_database()
initialise_auth_database()

# --------------------------------------------------
# AUTHENTICATION GATE
# --------------------------------------------------

if "sentinel_user" not in st.session_state:
    st.session_state.sentinel_user = None

st.title("🛡️ SentinelSIEM")
st.caption(
    "Security Operations Centre dashboard | Log monitoring, "
    "incident investigation and digital evidence management"
)

if user_count() == 0:
    st.info("First-time setup: create the initial administrator account.")
    with st.form("initial_admin_setup"):
        setup_username = st.text_input("Administrator username")
        setup_display = st.text_input("Administrator display name")
        setup_password = st.text_input("Password", type="password")
        setup_confirm = st.text_input("Confirm password", type="password")
        setup_submit = st.form_submit_button("Create Administrator")
    if setup_submit:
        if setup_password != setup_confirm:
            st.error("The passwords do not match.")
        else:
            try:
                create_first_admin(setup_username, setup_display, setup_password)
                st.success("Administrator created. Sign in below.")
                st.rerun()
            except Exception as exc:
                st.error(f"Could not create administrator: {exc}")
    st.stop()

# Refresh the account from the database on every rerun so disabled accounts
# and role changes take effect without relying on stale session data.
session_user = st.session_state.sentinel_user
if session_user:
    current_user = get_user(session_user.get("username", ""))
    if not current_user or not current_user["is_active"]:
        st.session_state.sentinel_user = None
        st.warning("Your account is unavailable. Please sign in again.")
        st.rerun()
    st.session_state.sentinel_user.update({
        "role": current_user["role"],
        "display_name": current_user["display_name"],
    })

if not st.session_state.sentinel_user:
    st.subheader("Sign in")
    with st.form("login_form"):
        login_username = st.text_input("Username")
        login_password = st.text_input("Password", type="password")
        login_submit = st.form_submit_button("Sign in")
    if login_submit:
        account = authenticate_user(login_username, login_password)
        if account:
            st.session_state.sentinel_user = account
            st.rerun()
        else:
            st.error("Invalid username or password, or the account is inactive.")
    st.stop()

current_user = st.session_state.sentinel_user
CURRENT_USERNAME = current_user["username"]
CURRENT_ROLE = current_user["role"]
IS_ADMIN = CURRENT_ROLE == "Administrator"
CAN_INVESTIGATE = CURRENT_ROLE in ("Administrator", "SOC Analyst")

with st.sidebar:
    st.success(f"Signed in: {current_user['display_name']}")
    st.caption(f"Role: {CURRENT_ROLE}")
    if st.button("Sign out", use_container_width=True):
        st.session_state.sentinel_user = None
        st.rerun()

    if IS_ADMIN:
        with st.expander("User Administration", expanded=False):
            st.markdown("**Create user account**")
            with st.form("create_user_form", clear_on_submit=True):
                new_username = st.text_input("New username")
                new_display_name = st.text_input("Display name")
                new_password = st.text_input("Temporary password", type="password")
                new_role = st.selectbox("Role", ROLES, index=1)
                create_user_submit = st.form_submit_button("Create user")
            if create_user_submit:
                try:
                    create_user(CURRENT_USERNAME, new_username, new_display_name, new_password, new_role)
                    st.success(f"Created account: {new_username}")
                    st.rerun()
                except Exception as exc:
                    st.error(f"Could not create user: {exc}")

            st.markdown("**Manage existing accounts**")
            accounts = list_users()
            if accounts:
                account_names = [u["username"] for u in accounts]
                selected_account_name = st.selectbox("Select account", account_names)
                selected_account = next(u for u in accounts if u["username"] == selected_account_name)
                if selected_account_name.lower() != CURRENT_USERNAME.lower():
                    role_choice = st.selectbox(
                        "Account role", ROLES,
                        index=ROLES.index(selected_account["role"]),
                        key="admin_role_choice",
                    )
                    if st.button("Save role", key="save_user_role"):
                        try:
                            update_user_role(CURRENT_USERNAME, selected_account_name, role_choice)
                            st.success("User role updated.")
                            st.rerun()
                        except Exception as exc:
                            st.error(str(exc))
                    active_label = "Deactivate account" if selected_account["is_active"] else "Activate account"
                    if st.button(active_label, key="toggle_user_active"):
                        try:
                            set_user_active(CURRENT_USERNAME, selected_account_name, not bool(selected_account["is_active"]))
                            st.success("Account status updated.")
                            st.rerun()
                        except Exception as exc:
                            st.error(str(exc))
                with st.form("reset_password_form"):
                    reset_password_value = st.text_input("Set new password", type="password")
                    reset_password_submit = st.form_submit_button("Reset selected user's password")
                if reset_password_submit:
                    try:
                        reset_user_password(CURRENT_USERNAME, selected_account_name, reset_password_value)
                        st.success("Password reset successfully.")
                    except Exception as exc:
                        st.error(str(exc))
            st.markdown("**Authentication activity**")
            auth_audit = get_auth_audit()
            if auth_audit:
                st.dataframe(pd.DataFrame(auth_audit), use_container_width=True, hide_index=True)


# --------------------------------------------------
# HELPER FUNCTIONS
# --------------------------------------------------

def safe_count(dataframe):
    """Return the number of rows in a dataframe, including empty frames."""
    return 0 if dataframe is None else len(dataframe)


def parse_timestamps(dataframe, column="timestamp"):
    """Return a copy with a parsed timestamp column when available."""
    result = dataframe.copy()

    if column in result.columns:
        result[column] = pd.to_datetime(
            result[column],
            errors="coerce",
            utc=True,
        )

    return result


def filter_by_period(dataframe, period, timestamp_column="timestamp"):
    """Filter a dataframe by a dashboard time window."""
    if dataframe.empty or timestamp_column not in dataframe.columns:
        return dataframe.copy()

    result = parse_timestamps(dataframe, timestamp_column)
    valid = result[result[timestamp_column].notna()].copy()

    if period == "All available data" or valid.empty:
        return valid

    now = pd.Timestamp.now(tz="UTC")
    windows = {
        "Last 24 hours": pd.Timedelta(hours=24),
        "Last 7 days": pd.Timedelta(days=7),
        "Last 30 days": pd.Timedelta(days=30),
    }

    cutoff = now - windows[period]
    return valid[valid[timestamp_column] >= cutoff].copy()


def first_available_column(dataframe, candidates):
    """Find the first available column from a list of candidate names."""
    for column in candidates:
        if column in dataframe.columns:
            return column
    return None


def display_empty_chart_message(message):
    st.info(message)


# --------------------------------------------------
# LOG SOURCE
# --------------------------------------------------

with st.sidebar:
    st.header("Log Source")

    uploaded = st.file_uploader(
        "Upload a CSV log file",
        type=["csv"],
        help=(
            "Expected columns include timestamp, event_type, username, "
            "source_ip and message."
        ),
    )

    use_sample = st.toggle(
        "Use included sample logs",
        value=uploaded is None,
    )

    st.divider()
    st.header("Analytics Filters")

    selected_period = st.selectbox(
        "Analysis period",
        [
            "All available data",
            "Last 24 hours",
            "Last 7 days",
            "Last 30 days",
        ],
        index=0,
    )

    st.caption(
        "The time filter affects the charts and alert table. "
        "Incident records remain available in the incident register."
    )


try:
    if uploaded is not None:
        logs = load_logs(uploaded)
    elif use_sample:
        logs = load_logs(ROOT / "data" / "sample_logs.csv")
    else:
        st.info("Upload a CSV file or enable the sample logs option.")
        st.stop()

except Exception as exc:
    st.error(f"Could not read logs: {exc}")
    st.stop()


if logs.empty:
    st.warning("No log records were found in the selected source.")
    st.stop()


# --------------------------------------------------
# DETECTION AND INCIDENT CORRELATION
# --------------------------------------------------

try:
    alerts = analyze_logs(logs)

    if alerts is None:
        alerts = pd.DataFrame()

    incidents_from_current_logs, alerts = correlate_alerts(alerts)

    if incidents_from_current_logs is None:
        incidents_from_current_logs = pd.DataFrame()

    if alerts is None:
        alerts = pd.DataFrame()

    # Only administrators and SOC analysts may persist new incidents.
    # Viewers can still inspect detections generated from the selected logs.
    if CAN_INVESTIGATE:
        persistent_ids = save_incidents(
            incidents_from_current_logs,
            alerts,
        )
        if not alerts.empty and "incident_id" in alerts.columns:
            alerts["incident_id"] = (
                alerts["incident_id"]
                .astype(str)
                .map(persistent_ids)
                .fillna(alerts["incident_id"])
            )

    # All roles can read the existing persistent incident register.
    incidents = get_incidents()

    if incidents is None:
        incidents = pd.DataFrame()

except Exception as exc:
    st.error(f"Detection or incident processing failed: {exc}")
    st.exception(exc)
    st.stop()


# --------------------------------------------------
# APPLY ANALYTICS TIME FILTER
# --------------------------------------------------

filtered_logs = filter_by_period(
    logs,
    selected_period,
    "timestamp",
)

filtered_alerts = filter_by_period(
    alerts,
    selected_period,
    "timestamp",
) if "timestamp" in alerts.columns else alerts.copy()


# --------------------------------------------------
# STAGE 9: SOC OVERVIEW
# --------------------------------------------------

st.divider()
st.header("SOC Overview")
st.caption(
    f"Showing analytics for: {selected_period}. "
    "Metrics are calculated from the selected log source unless stated otherwise."
)

event_type_column = first_available_column(
    filtered_logs,
    ["event_type", "EventType", "event"],
)

failed_logins = 0
successful_logins = 0

if event_type_column:
    event_values = (
        filtered_logs[event_type_column]
        .astype(str)
        .str.lower()
    )
    failed_logins = int(event_values.isin(
        ["login_failed", "failed_login", "4625"]
    ).sum())
    successful_logins = int(event_values.isin(
        ["login_success", "successful_login", "4624"]
    ).sum())

severity_column = first_available_column(
    filtered_alerts,
    ["severity", "Severity"],
)

critical_alerts = 0
high_alerts = 0

if severity_column:
    severity_values = filtered_alerts[severity_column].astype(str).str.title()
    critical_alerts = int((severity_values == "Critical").sum())
    high_alerts = int((severity_values == "High").sum())

open_incidents = 0
investigating_incidents = 0
critical_incidents = 0

if not incidents.empty:
    if "status" in incidents.columns:
        status_values = incidents["status"].astype(str)
        open_incidents = int((status_values == "Open").sum())
        investigating_incidents = int(
            (status_values == "Investigating").sum()
        )

    if "severity" in incidents.columns:
        critical_incidents = int(
            (incidents["severity"].astype(str).str.title() == "Critical").sum()
        )

evidence_total = 0
if not incidents.empty and "incident_id" in incidents.columns:
    for incident_ref in incidents["incident_id"].dropna().astype(str):
        try:
            evidence_total += safe_count(get_evidence(incident_ref))
        except Exception:
            # Keep the dashboard available if one evidence lookup fails.
            continue

k1, k2, k3, k4 = st.columns(4)
k1.metric("Events Analyzed", len(filtered_logs))
k2.metric("Failed Logins", failed_logins)
k3.metric("Critical Alerts", critical_alerts)
k4.metric("High Alerts", high_alerts)

k5, k6, k7, k8 = st.columns(4)
k5.metric("Total Alerts", len(filtered_alerts))
k6.metric("Open Incidents", open_incidents)
k7.metric("Investigating Incidents", investigating_incidents)
k8.metric("Evidence Records", evidence_total)


# --------------------------------------------------
# EVENT AND ALERT DISTRIBUTION
# --------------------------------------------------

st.divider()
st.subheader("Security Event Analytics")

chart_left, chart_right = st.columns(2)

with chart_left:
    st.markdown("**Events by type**")

    if event_type_column:
        event_counts = (
            filtered_logs[event_type_column]
            .fillna("Unknown")
            .astype(str)
            .value_counts()
            .rename_axis("Event Type")
            .reset_index(name="Count")
        )

        if not event_counts.empty:
            figure = px.bar(
                event_counts,
                x="Event Type",
                y="Count",
                title="Event Distribution",
                text="Count",
            )
            figure.update_layout(
                xaxis_title="Event Type",
                yaxis_title="Number of Events",
            )
            st.plotly_chart(figure, use_container_width=True)
        else:
            display_empty_chart_message("No event types are available.")
    else:
        display_empty_chart_message(
            "The uploaded logs do not contain an event_type column."
        )

with chart_right:
    st.markdown("**Alerts by severity**")

    if not filtered_alerts.empty and severity_column:
        severity_counts = (
            filtered_alerts[severity_column]
            .fillna("Unknown")
            .astype(str)
            .str.title()
            .value_counts()
            .rename_axis("Severity")
            .reset_index(name="Count")
        )

        figure = px.pie(
            severity_counts,
            names="Severity",
            values="Count",
            title="Alert Severity Distribution",
            hole=0.35,
        )
        st.plotly_chart(figure, use_container_width=True)
    else:
        display_empty_chart_message(
            "No alerts are available for the selected period."
        )


# --------------------------------------------------
# ALERT ACTIVITY TIMELINE
# --------------------------------------------------

st.subheader("Alert Activity Over Time")

if not filtered_alerts.empty and "timestamp" in filtered_alerts.columns:
    timeline_data = parse_timestamps(filtered_alerts, "timestamp")
    timeline_data = timeline_data.dropna(subset=["timestamp"])

    if not timeline_data.empty:
        timeline_data["Date"] = (
            timeline_data["timestamp"].dt.floor("D")
        )

        daily_counts = (
            timeline_data.groupby("Date")
            .size()
            .reset_index(name="Alerts")
        )

        figure = px.line(
            daily_counts,
            x="Date",
            y="Alerts",
            markers=True,
            title="Daily Alert Volume",
        )
        figure.update_layout(
            xaxis_title="Date",
            yaxis_title="Number of Alerts",
        )
        st.plotly_chart(figure, use_container_width=True)
    else:
        display_empty_chart_message(
            "Alert timestamps could not be interpreted as dates."
        )
else:
    display_empty_chart_message(
        "Alert timestamps are not available for the activity timeline."
    )


# --------------------------------------------------
# TOP SOURCE IPS, TARGETED USERS AND DETECTION RULES
# --------------------------------------------------

st.subheader("Detection Insights")

insight_left, insight_middle, insight_right = st.columns(3)

source_ip_column = first_available_column(
    filtered_alerts,
    ["source_ip", "Source IP", "src_ip"],
)
username_column = first_available_column(
    filtered_alerts,
    ["username", "Username", "user"],
)
rule_column = first_available_column(
    filtered_alerts,
    ["rule", "detection_rule", "rule_name"],
)

with insight_left:
    st.markdown("**Top source IP addresses**")

    if source_ip_column and not filtered_alerts.empty:
        top_ips = (
            filtered_alerts[source_ip_column]
            .fillna("Unknown")
            .astype(str)
            .value_counts()
            .head(10)
            .rename_axis("Source IP")
            .reset_index(name="Alerts")
        )
        top_ips = top_ips[top_ips["Source IP"].ne("Unknown")]

        if not top_ips.empty:
            figure = px.bar(
                top_ips,
                x="Alerts",
                y="Source IP",
                orientation="h",
                title="Sources Generating Alerts",
            )
            figure.update_layout(yaxis={"categoryorder": "total ascending"})
            st.plotly_chart(figure, use_container_width=True)
        else:
            display_empty_chart_message("No source IP data is available.")
    else:
        display_empty_chart_message("Source IP data is unavailable.")

with insight_middle:
    st.markdown("**Most affected usernames**")

    if username_column and not filtered_alerts.empty:
        top_users = (
            filtered_alerts[username_column]
            .fillna("Unknown")
            .astype(str)
            .value_counts()
            .head(10)
            .rename_axis("Username")
            .reset_index(name="Alerts")
        )
        top_users = top_users[top_users["Username"].ne("Unknown")]

        if not top_users.empty:
            figure = px.bar(
                top_users,
                x="Alerts",
                y="Username",
                orientation="h",
                title="Users Appearing in Alerts",
            )
            figure.update_layout(yaxis={"categoryorder": "total ascending"})
            st.plotly_chart(figure, use_container_width=True)
        else:
            display_empty_chart_message("No username data is available.")
    else:
        display_empty_chart_message("Username data is unavailable.")

with insight_right:
    st.markdown("**Most triggered detection rules**")

    if rule_column and not filtered_alerts.empty:
        top_rules = (
            filtered_alerts[rule_column]
            .fillna("Unknown")
            .astype(str)
            .value_counts()
            .head(10)
            .rename_axis("Detection Rule")
            .reset_index(name="Alerts")
        )

        if not top_rules.empty:
            figure = px.bar(
                top_rules,
                x="Alerts",
                y="Detection Rule",
                orientation="h",
                title="Detection Rule Frequency",
            )
            figure.update_layout(yaxis={"categoryorder": "total ascending"})
            st.plotly_chart(figure, use_container_width=True)
        else:
            display_empty_chart_message("No detection rule data is available.")
    else:
        display_empty_chart_message("Detection rule data is unavailable.")


# --------------------------------------------------
# INCIDENT STATUS ANALYTICS
# --------------------------------------------------

st.divider()
st.subheader("Incident Status Overview")

if not incidents.empty and "status" in incidents.columns:
    status_counts = (
        incidents["status"]
        .fillna("Unknown")
        .astype(str)
        .value_counts()
        .rename_axis("Status")
        .reset_index(name="Incidents")
    )

    status_figure = px.bar(
        status_counts,
        x="Status",
        y="Incidents",
        color="Status",
        title="Persistent Incident Register",
        text="Incidents",
    )
    st.plotly_chart(status_figure, use_container_width=True)
else:
    display_empty_chart_message(
        "There are no stored incidents to display."
    )


# --------------------------------------------------
# DETECTION ALERT REGISTER
# --------------------------------------------------

st.divider()
st.header("Detection Alerts")

if filtered_alerts.empty:
    st.info("No alerts were detected for the selected period.")
else:
    severity_options = ["Critical", "High", "Medium", "Low"]

    if severity_column:
        available_severities = (
            filtered_alerts[severity_column]
            .dropna()
            .astype(str)
            .str.title()
            .unique()
            .tolist()
        )
        default_severities = [
            item for item in severity_options
            if item in available_severities
        ]

        selected_severities = st.multiselect(
            "Filter by severity",
            options=severity_options,
            default=default_severities or severity_options,
        )

        alert_display = filtered_alerts[
            filtered_alerts[severity_column]
            .astype(str)
            .str.title()
            .isin(selected_severities)
        ]
    else:
        alert_display = filtered_alerts

    st.dataframe(
        alert_display,
        use_container_width=True,
        hide_index=True,
    )

    st.download_button(
        "Download filtered alerts as CSV",
        data=alert_display.to_csv(index=False).encode("utf-8"),
        file_name="sentinelsiem_alerts.csv",
        mime="text/csv",
    )


# --------------------------------------------------
# INCIDENT INVESTIGATION
# --------------------------------------------------

st.divider()
st.header("Incident Investigation")

if incidents.empty:
    st.info(
        "No incidents have been detected or stored yet. "
        "Upload logs that trigger detection rules to populate the register."
    )

else:
    # Incident register summary.
    total_incidents = len(incidents)

    status_series = (
        incidents["status"].astype(str)
        if "status" in incidents.columns
        else pd.Series([], dtype=str)
    )

    severity_series = (
        incidents["severity"].astype(str).str.title()
        if "severity" in incidents.columns
        else pd.Series([], dtype=str)
    )

    col1, col2, col3, col4 = st.columns(4)
    col1.metric("Total Incidents", total_incidents)
    col2.metric("Open Incidents", int((status_series == "Open").sum()))
    col3.metric(
        "Investigating",
        int((status_series == "Investigating").sum()),
    )
    col4.metric(
        "Critical Incidents",
        int((severity_series == "Critical").sum()),
    )

    st.subheader("Incident Register")
    st.dataframe(
        incidents,
        use_container_width=True,
        hide_index=True,
    )

    incident_id_column = first_available_column(
        incidents,
        ["incident_id", "incident_ref"],
    )

    if incident_id_column is None:
        st.error(
            "The incident register does not contain an incident_id "
            "or incident_ref column. Check get_incidents() in "
            "src/incident_store.py."
        )
        st.stop()

    incident_ids = (
        incidents[incident_id_column]
        .dropna()
        .astype(str)
        .tolist()
    )

    if not incident_ids:
        st.info("There are no selectable incident references.")
        st.stop()

    selected_incident = st.selectbox(
        "Select an incident to investigate",
        incident_ids,
    )

    selected = incidents[
        incidents[incident_id_column].astype(str) == selected_incident
    ].iloc[0]

    st.divider()
    st.subheader(f"Investigation: {selected_incident}")

    detail_left, detail_right = st.columns(2)

    with detail_left:
        st.write("**Incident Title:**", selected.get("title", "N/A"))
        st.write("**Severity:**", selected.get("severity", "N/A"))
        st.write("**Current Status:**", selected.get("status", "N/A"))
        st.write("**Alert Count:**", selected.get("alert_count", "N/A"))

    with detail_right:
        st.write(
            "**Affected Users:**",
            selected.get("affected_users", "N/A"),
        )
        st.write("**Source IPs:**", selected.get("source_ips", "N/A"))
        st.write("**First Seen:**", selected.get("first_seen", "N/A"))
        st.write("**Last Seen:**", selected.get("last_seen", "N/A"))

    # --------------------------------------------------
    # UPDATE INCIDENT STATUS
    # --------------------------------------------------

    st.divider()
    st.subheader("Update Incident Status")

    statuses = ["Open", "Investigating", "Resolved", "Closed"]
    current_status = str(selected.get("status", "Open"))

    if CAN_INVESTIGATE:
        with st.form("incident_status_form"):
            new_status = st.selectbox(
                "Select New Status",
                statuses,
                index=statuses.index(current_status)
                if current_status in statuses else 0,
            )
            update_status_button = st.form_submit_button("Update Incident Status")
            if update_status_button:
                if new_status == current_status:
                    st.info("The incident already has that status.")
                else:
                    try:
                        update_incident_status(selected_incident, new_status, CURRENT_USERNAME)
                        st.success("Incident status updated successfully.")
                        st.rerun()
                    except Exception as exc:
                        st.error(f"Could not update incident status: {exc}")
    else:
        st.info("Read-only access: you cannot change incident status.")

    # --------------------------------------------------
    # INVESTIGATION NOTES
    # --------------------------------------------------

    st.divider()
    st.subheader("Investigation Notes")

    if CAN_INVESTIGATE:
        with st.form("investigation_note_form"):
            note = st.text_area(
                "Investigation Findings",
                placeholder=(
                    "Document your investigation findings here.\\n\\n"
                    "Include:\\n"
                    "- What happened?\\n"
                    "- Which accounts or systems were affected?\\n"
                    "- What evidence was reviewed?\\n"
                    "- What actions were taken?\\n"
                    "- What is your conclusion?"
                ),
                height=180,
            )
            save_note_button = st.form_submit_button("Save Investigation Note")
            if save_note_button:
                if not note.strip():
                    st.error("Please enter investigation findings.")
                else:
                    try:
                        add_investigation_note(selected_incident, CURRENT_USERNAME, note.strip())
                        st.success("Investigation note saved successfully.")
                        st.rerun()
                    except Exception as exc:
                        st.error(f"Could not save investigation note: {exc}")
    else:
        st.info("Read-only access: you cannot add investigation notes.")

    # INVESTIGATION HISTORY
    # --------------------------------------------------

    st.divider()
    st.subheader("Investigation History")

    try:
        notes = get_investigation_notes(selected_incident)

        if notes is None or notes.empty:
            st.info("No investigation notes have been recorded.")
        else:
            for _, record in notes.iterrows():
                with st.container(border=True):
                    st.write(f"**Analyst:** {record.get('analyst', 'N/A')}")
                    st.write(record.get("note", ""))
                    st.caption(
                        f"Recorded: {record.get('created_at', 'N/A')}"
                    )
    except Exception as exc:
        st.error(f"Could not load investigation history: {exc}")

    # --------------------------------------------------
    # RELATED SECURITY ALERTS
    # --------------------------------------------------

    st.divider()
    st.subheader("Related Security Alerts")

    try:
        related_alerts = get_incident_alerts(selected_incident)

        if related_alerts is None or related_alerts.empty:
            st.info(
                "No security alerts are associated with this incident."
            )
        else:
            st.dataframe(
                related_alerts,
                use_container_width=True,
                hide_index=True,
            )
    except Exception as exc:
        st.error(f"Could not load related alerts: {exc}")

    # --------------------------------------------------
    # DIGITAL EVIDENCE MANAGEMENT
    # --------------------------------------------------

    st.divider()
    st.header("Digital Evidence Management")

    st.write(
        "Upload, manage, download and verify digital evidence "
        "associated with this security incident."
    )

    st.subheader("Upload Evidence")

    if CAN_INVESTIGATE:
        with st.form(
            f"evidence_upload_form_{selected_incident}",
            clear_on_submit=True,
        ):
            evidence_file = st.file_uploader(
                "Select evidence file",
                help="Maximum file size: 25 MB.",
                key=f"evidence_file_{selected_incident}",
            )
            evidence_description = st.text_area(
                "Evidence description",
                placeholder="Describe the evidence, its source, and why it is relevant.",
                key=f"evidence_description_{selected_incident}",
            )
            upload_submitted = st.form_submit_button("Upload Evidence")
            if upload_submitted:
                if evidence_file is None:
                    st.error("Please select a file.")
                elif evidence_file.size > 25 * 1024 * 1024:
                    st.error("The maximum upload size is 25 MB.")
                else:
                    try:
                        result = add_evidence(
                            incident_ref=selected_incident,
                            original_filename=evidence_file.name,
                            file_bytes=evidence_file.getvalue(),
                            uploaded_by=CURRENT_USERNAME,
                            description=evidence_description,
                            content_type=evidence_file.type or "application/octet-stream",
                        )
                        st.success(f"Evidence uploaded successfully: {result.get('filename', evidence_file.name)}")
                        st.write("**Evidence ID:**", result.get("evidence_id", "N/A"))
                        if result.get("sha256"):
                            st.write("**SHA-256:**")
                            st.code(result["sha256"])
                        st.rerun()
                    except Exception as exc:
                        st.error(f"Evidence upload failed: {exc}")
    else:
        st.info("Read-only access: evidence upload is disabled.")

    # --------------------------------------------------
    # EVIDENCE REGISTER
    # --------------------------------------------------

    st.subheader("Evidence Register")

    try:
        evidence_records = get_evidence(selected_incident)

        if evidence_records is None or evidence_records.empty:
            st.info(
                "No evidence files have been attached to this incident."
            )
        else:
            st.metric("Evidence Files", len(evidence_records))

            display_evidence = evidence_records.drop(
                columns=["evidence_id"],
                errors="ignore",
            )

            st.dataframe(
                display_evidence,
                use_container_width=True,
                hide_index=True,
            )

            st.subheader("Download and Verify Evidence")

            evidence_options = (
                evidence_records["evidence_id"].astype(str).tolist()
            )

            filename_column = (
                "original_filename"
                if "original_filename" in evidence_records.columns
                else None
            )

            selected_evidence = st.selectbox(
                "Select evidence record",
                evidence_options,
                format_func=lambda evidence_id: (
                    str(
                        evidence_records.loc[
                            evidence_records["evidence_id"].astype(str)
                            == evidence_id,
                            filename_column,
                        ].iloc[0]
                    )
                    if filename_column else evidence_id
                ),
                key=f"selected_evidence_{selected_incident}",
            )

            selected_record = evidence_records[
                evidence_records["evidence_id"].astype(str)
                == selected_evidence
            ].iloc[0]

            st.write("**Evidence ID:**", selected_evidence)

            if "sha256" in selected_record.index:
                st.write("**Original SHA-256 hash:**")
                st.code(str(selected_record["sha256"]))

            try:
                file_bytes, filename, content_type = get_evidence_file(
                    selected_evidence
                )

                st.download_button(
                    label="Download Evidence",
                    data=file_bytes,
                    file_name=filename,
                    mime=content_type,
                    key=f"download_{selected_evidence}",
                )
            except Exception as exc:
                st.error(f"Download unavailable: {exc}")

            st.write("**File Integrity Verification**")

            if CAN_INVESTIGATE and st.button(
                "Verify Evidence Integrity",
                key=f"verify_{selected_evidence}",
            ):
                try:
                    result = verify_evidence(selected_evidence, CURRENT_USERNAME)

                    if result.get("valid"):
                        st.success(result.get("message", "Integrity check passed."))
                    else:
                        st.error(result.get("message", "Integrity check failed."))

                    st.write("**Expected SHA-256:**")
                    st.code(result.get("expected_hash") or "Unavailable")

                    st.write("**Calculated SHA-256:**")
                    st.code(result.get("actual_hash") or "File unavailable")

                except Exception as exc:
                    st.error(f"Verification failed: {exc}")

            if not CAN_INVESTIGATE:
                st.caption("Read-only access: evidence integrity verification is disabled.")
    except Exception as exc:
        st.error(f"Could not load the evidence register: {exc}")

    # --------------------------------------------------
    # INCIDENT AUDIT TRAIL
    # --------------------------------------------------

    st.divider()
    st.subheader("Incident Audit Trail")

    try:
        audit_history = get_incident_audit(selected_incident)

        if audit_history is None or audit_history.empty:
            st.info("No audit events have been recorded yet.")
        else:
            st.dataframe(
                audit_history,
                use_container_width=True,
                hide_index=True,
            )
    except Exception as exc:
        st.error(f"Could not load the incident audit trail: {exc}")

    st.warning(
        "Review available security evidence before classifying an incident "
        "as a confirmed threat. The application audit trail is not "
        "tamper-proof."
    )

    # --------------------------------------------------
    # INCIDENT REPORT GENERATION
    # --------------------------------------------------

    st.divider()
    st.header("Automated Incident Reports")

    st.write(
        "Generate a downloadable PDF containing incident details, "
        "security alerts, evidence records, investigation notes "
        "and audit history."
    )

    try:
        report_pdf = generate_incident_report(selected_incident)

        st.download_button(
            label="Download Incident Report (PDF)",
            data=report_pdf,
            file_name=f"{selected_incident}_report.pdf",
            mime="application/pdf",
            key=f"report_{selected_incident}",
        )

        st.caption(
            "The report is generated from the latest records stored "
            "for this incident."
        )

    except Exception as exc:
        st.error(f"Could not generate the incident report: {exc}")


# --------------------------------------------------
# RAW LOG EVENTS
# --------------------------------------------------

st.divider()
st.header("Raw Log Events")
st.dataframe(
    filtered_logs,
    use_container_width=True,
    hide_index=True,
)

st.download_button(
    "Download normalized logs",
    data=filtered_logs.to_csv(index=False).encode("utf-8"),
    file_name="normalized_logs.csv",
    mime="text/csv",
)
