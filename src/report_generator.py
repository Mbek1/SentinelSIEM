
import io
import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from xml.sax.saxutils import escape

import pandas as pd

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT
from reportlab.lib.pagesizes import landscape, A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import mm
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
    PageBreak
)


# --------------------------------------------------
# CONFIGURATION
# --------------------------------------------------

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = PROJECT_ROOT / "data"
DB_PATH = DATA_DIR / "sentinel_siem.db"


# --------------------------------------------------
# DATABASE
# --------------------------------------------------

def get_connection():
    if not DB_PATH.exists():
        raise FileNotFoundError(
            "SentinelSIEM database was not found."
        )

    connection = sqlite3.connect(DB_PATH)
    connection.row_factory = sqlite3.Row
    return connection


def fetch_report_data(incident_ref):

    with get_connection() as connection:

        incident = connection.execute("""
            SELECT *
            FROM incidents
            WHERE incident_ref = ?
        """, (incident_ref,)).fetchone()

        if not incident:
            raise ValueError("Incident not found.")

        notes = connection.execute("""
            SELECT analyst, note, created_at
            FROM investigation_notes
            WHERE incident_ref = ?
            ORDER BY created_at ASC, id ASC
        """, (incident_ref,)).fetchall()

        audit = connection.execute("""
            SELECT analyst, action, details, created_at
            FROM incident_audit
            WHERE incident_ref = ?
            ORDER BY created_at ASC, id ASC
        """, (incident_ref,)).fetchall()

        evidence = connection.execute("""
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
            ORDER BY uploaded_at ASC
        """, (incident_ref,)).fetchall()

    incident = dict(incident)

    try:
        alerts = json.loads(incident.get("alerts_json") or "[]")
    except (TypeError, json.JSONDecodeError):
        alerts = []

    return {
        "incident": incident,
        "alerts": alerts,
        "notes": [dict(row) for row in notes],
        "audit": [dict(row) for row in audit],
        "evidence": [dict(row) for row in evidence]
    }


# --------------------------------------------------
# PDF HELPERS
# --------------------------------------------------

def safe_text(value):
    if value is None:
        return "N/A"

    if isinstance(value, float) and pd.isna(value):
        return "N/A"

    value = str(value).strip()

    return escape(value) if value else "N/A"


def make_paragraph(value, style):
    return Paragraph(safe_text(value), style)


def make_table(rows, widths, header=True):

    table = Table(
        rows,
        colWidths=widths,
        repeatRows=1 if header else 0,
        hAlign="LEFT"
    )

    commands = [
        ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#CBD5E1")),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 5),
        ("RIGHTPADDING", (0, 0), (-1, -1), 5),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
    ]

    if header:
        commands.extend([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#172554")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ])

    for row_index in range(1 if header else 0, len(rows)):
        if row_index % 2 == 0:
            commands.append((
                "BACKGROUND",
                (0, row_index),
                (-1, row_index),
                colors.HexColor("#F1F5F9")
            ))

    table.setStyle(TableStyle(commands))
    return table


def page_footer(canvas, document):
    canvas.saveState()

    canvas.setFont("Helvetica", 8)
    canvas.setFillColor(colors.HexColor("#64748B"))

    canvas.drawString(
        15 * mm,
        10 * mm,
        "SentinelSIEM | Security Incident Report"
    )

    canvas.drawRightString(
        landscape(A4)[0] - 15 * mm,
        10 * mm,
        f"Page {document.page}"
    )

    canvas.restoreState()


# --------------------------------------------------
# GENERATE INCIDENT PDF
# --------------------------------------------------

def generate_incident_report(incident_ref):

    data = fetch_report_data(incident_ref)

    incident = data["incident"]
    alerts = data["alerts"]
    notes = data["notes"]
    audit = data["audit"]
    evidence = data["evidence"]

    buffer = io.BytesIO()

    page_width, page_height = landscape(A4)

    document = SimpleDocTemplate(
        buffer,
        pagesize=landscape(A4),
        rightMargin=15 * mm,
        leftMargin=15 * mm,
        topMargin=17 * mm,
        bottomMargin=18 * mm,
        title=f"SentinelSIEM Incident Report - {incident_ref}",
        author="SentinelSIEM"
    )

    styles = getSampleStyleSheet()

    title_style = ParagraphStyle(
        "ReportTitle",
        parent=styles["Title"],
        fontName="Helvetica-Bold",
        fontSize=21,
        leading=25,
        textColor=colors.HexColor("#172554"),
        alignment=TA_CENTER,
        spaceAfter=8
    )

    subtitle_style = ParagraphStyle(
        "ReportSubtitle",
        parent=styles["Normal"],
        fontSize=9,
        textColor=colors.HexColor("#64748B"),
        alignment=TA_CENTER,
        spaceAfter=16
    )

    heading_style = ParagraphStyle(
        "SectionHeading",
        parent=styles["Heading2"],
        fontName="Helvetica-Bold",
        fontSize=13,
        textColor=colors.HexColor("#1E3A8A"),
        spaceBefore=12,
        spaceAfter=7
    )

    body_style = ParagraphStyle(
        "ReportBody",
        parent=styles["BodyText"],
        fontSize=8,
        leading=11,
        spaceAfter=3,
        wordWrap="CJK"
    )

    small_style = ParagraphStyle(
        "SmallText",
        parent=body_style,
        fontSize=7,
        leading=9
    )

    header_style = ParagraphStyle(
        "TableHeader",
        parent=small_style,
        textColor=colors.white,
        fontName="Helvetica-Bold"
    )

    generated_at = datetime.now(timezone.utc).isoformat()

    story = []

    # --------------------------------------------------
    # REPORT TITLE
    # --------------------------------------------------

    story.append(
        Paragraph("SENTINELSIEM", title_style)
    )

    story.append(
        Paragraph(
            "SECURITY INCIDENT INVESTIGATION REPORT",
            subtitle_style
        )
    )

    story.append(
        Paragraph(
            f"Report Reference: {safe_text(incident_ref)}",
            styles["Heading2"]
        )
    )

    story.append(
        Paragraph(
            f"Generated: {safe_text(generated_at)}",
            body_style
        )
    )

    story.append(Spacer(1, 8))

    # --------------------------------------------------
    # INCIDENT DETAILS
    # --------------------------------------------------

    story.append(
        Paragraph("1. Incident Overview", heading_style)
    )

    overview_rows = [
        [
            make_paragraph("Incident Reference", header_style),
            make_paragraph("Title", header_style),
            make_paragraph("Severity", header_style),
            make_paragraph("Status", header_style)
        ],
        [
            make_paragraph(incident.get("incident_ref"), body_style),
            make_paragraph(incident.get("title"), body_style),
            make_paragraph(incident.get("severity"), body_style),
            make_paragraph(incident.get("status"), body_style)
        ],
        [
            make_paragraph("First Seen", header_style),
            make_paragraph("Last Seen", header_style),
            make_paragraph("Alert Count", header_style),
            make_paragraph("Created At", header_style)
        ],
        [
            make_paragraph(incident.get("first_seen"), body_style),
            make_paragraph(incident.get("last_seen"), body_style),
            make_paragraph(incident.get("alert_count"), body_style),
            make_paragraph(incident.get("created_at"), body_style)
        ]
    ]

    story.append(
        make_table(
            overview_rows,
            [48 * mm, 83 * mm, 40 * mm, 91 * mm],
            header=False
        )
    )

    story.append(Spacer(1, 8))

    story.append(
        Paragraph("Source IP Addresses", heading_style)
    )

    story.append(
        Paragraph(
            safe_text(incident.get("source_ips")),
            body_style
        )
    )

    story.append(
        Paragraph("Affected Users", heading_style)
    )

    story.append(
        Paragraph(
            safe_text(incident.get("affected_users")),
            body_style
        )
    )

    # --------------------------------------------------
    # SECURITY ALERTS
    # --------------------------------------------------

    story.append(
        Paragraph("2. Related Security Alerts", heading_style)
    )

    if alerts:

        alert_rows = [[
            make_paragraph("Timestamp", header_style),
            make_paragraph("Event ID", header_style),
            make_paragraph("Detection Rule", header_style),
            make_paragraph("Severity", header_style),
            make_paragraph("Username", header_style),
            make_paragraph("Source IP", header_style),
            make_paragraph("Description", header_style)
        ]]

        for alert in alerts:

            alert_rows.append([
                make_paragraph(alert.get("timestamp"), small_style),
                make_paragraph(alert.get("event_id"), small_style),
                make_paragraph(alert.get("rule"), small_style),
                make_paragraph(alert.get("severity"), small_style),
                make_paragraph(alert.get("username"), small_style),
                make_paragraph(alert.get("source_ip"), small_style),
                make_paragraph(alert.get("description"), small_style)
            ])

        story.append(
            make_table(
                alert_rows,
                [
                    35 * mm,
                    16 * mm,
                    38 * mm,
                    19 * mm,
                    27 * mm,
                    25 * mm,
                    102 * mm
                ]
            )
        )

    else:
        story.append(
            Paragraph("No related alerts were recorded.", body_style)
        )

    # --------------------------------------------------
    # DIGITAL EVIDENCE
    # --------------------------------------------------

    story.append(
        Paragraph("3. Digital Evidence Register", heading_style)
    )

    if evidence:

        evidence_rows = [[
            make_paragraph("Filename", header_style),
            make_paragraph("SHA-256 Hash", header_style),
            make_paragraph("Size (bytes)", header_style),
            make_paragraph("Description", header_style),
            make_paragraph("Uploaded By", header_style),
            make_paragraph("Upload Time", header_style)
        ]]

        for item in evidence:

            evidence_rows.append([
                make_paragraph(item.get("original_filename"), small_style),
                make_paragraph(item.get("sha256"), small_style),
                make_paragraph(item.get("file_size"), small_style),
                make_paragraph(item.get("description"), small_style),
                make_paragraph(item.get("uploaded_by"), small_style),
                make_paragraph(item.get("uploaded_at"), small_style)
            ])

        story.append(
            make_table(
                evidence_rows,
                [
                    40 * mm,
                    78 * mm,
                    22 * mm,
                    52 * mm,
                    30 * mm,
                    40 * mm
                ]
            )
        )

        story.append(Spacer(1, 5))

        story.append(
            Paragraph(
                "The hashes shown above are the values recorded when "
                "the evidence files were uploaded. They are not, by "
                "themselves, proof of authenticity or chain of custody.",
                small_style
            )
        )

    else:

        story.append(
            Paragraph(
                "No evidence files were attached to this incident.",
                body_style
            )
        )

    # --------------------------------------------------
    # INVESTIGATION NOTES
    # --------------------------------------------------

    story.append(
        Paragraph("4. Investigation Notes", heading_style)
    )

    if notes:

        for note in notes:

            story.append(
                Paragraph(
                    f"<b>Analyst:</b> {safe_text(note.get('analyst'))}",
                    body_style
                )
            )

            story.append(
                Paragraph(
                    f"<b>Date:</b> {safe_text(note.get('created_at'))}",
                    small_style
                )
            )

            story.append(
                Paragraph(
                    safe_text(note.get("note")).replace("\n", "<br/>"),
                    body_style
                )
            )

            story.append(Spacer(1, 7))

    else:

        story.append(
            Paragraph(
                "No investigation notes have been recorded.",
                body_style
            )
        )

    # --------------------------------------------------
    # AUDIT TRAIL
    # --------------------------------------------------

    story.append(
        Paragraph("5. Incident Audit Trail", heading_style)
    )

    if audit:

        audit_rows = [[
            make_paragraph("Date and Time", header_style),
            make_paragraph("Analyst", header_style),
            make_paragraph("Action", header_style),
            make_paragraph("Details", header_style)
        ]]

        for event in audit:

            audit_rows.append([
                make_paragraph(event.get("created_at"), small_style),
                make_paragraph(event.get("analyst"), small_style),
                make_paragraph(event.get("action"), small_style),
                make_paragraph(event.get("details"), small_style)
            ])

        story.append(
            make_table(
                audit_rows,
                [
                    48 * mm,
                    35 * mm,
                    48 * mm,
                    131 * mm
                ]
            )
        )

    else:

        story.append(
            Paragraph(
                "No audit events have been recorded.",
                body_style
            )
        )

    # --------------------------------------------------
    # REPORT DISCLAIMER
    # --------------------------------------------------

    story.append(Spacer(1, 15))

    story.append(
        Paragraph("6. Report Disclaimer", heading_style)
    )

    story.append(
        Paragraph(
            "This report is generated from records currently stored "
            "in SentinelSIEM. Automated alerts and correlation results "
            "are investigation leads, not proof of malicious activity. "
            "The report does not independently establish the authenticity, "
            "origin or legal admissibility of evidence. Findings should "
            "be validated by an appropriately authorised investigator. "
            "The report is a generated snapshot and does not include "
            "the original evidence file contents.",
            body_style
        )
    )

    document.build(
        story,
        onFirstPage=page_footer,
        onLaterPages=page_footer
    )

    buffer.seek(0)

    return buffer.getvalue()
