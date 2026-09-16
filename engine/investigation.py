from datetime import datetime, timezone


VALID_DISPOSITIONS = {
    "True Positive",
    "False Positive",
    "Benign Positive",
    "Needs Investigation"
}

VALID_STATUSES = {
    "New",
    "Investigating",
    "Resolved"
}


def unique_values(events, field):
    values = []

    for event in events:
        value = event.get(field)

        if value is not None and value not in values:
            values.append(value)

    return values


def build_timeline(evidence):
    """
    Convert alert evidence into a chronological investigation timeline.
    """

    timeline = []

    for event in evidence:
        timeline.append({
            "event_uid": event.get("event_uid"),
            "timestamp": event.get("timestamp"),
            "event_type": event.get("event_type"),
            "host": event.get("host"),
            "username": event.get("username"),
            "source_ip": event.get("source_ip"),
            "process": event.get("process"),
            "command_line": event.get("command_line"),
            "status": event.get("status"),
            "raw_event": event.get("raw_event")
        })

    timeline.sort(
        key=lambda item: (
            item.get("timestamp") is None,
            item.get("timestamp") or ""
        )
    )

    return timeline


def build_investigation(alert):
    """
    Build an analyst-friendly investigation object from a generated alert.
    """

    evidence = alert.get("evidence", [])

    entities = {
        "hosts": unique_values(evidence, "host"),
        "users": unique_values(evidence, "username"),
        "source_ips": unique_values(evidence, "source_ip"),
        "destination_ips": unique_values(
            evidence,
            "destination_ip"
        ),
        "processes": unique_values(evidence, "process")
    }

    return {
        "alert_id": alert.get("alert_id"),
        "rule_id": alert.get("rule_id"),
        "rule_name": alert.get("rule_name"),

        "title": alert.get("title"),
        "description": alert.get("description"),
        "why_fired": alert.get("reason"),

        "severity": alert.get("severity"),
        "risk_score": alert.get("risk_score"),

        "mitre": alert.get("mitre"),

        "entities": entities,

        "evidence_count": len(evidence),

        "timeline": build_timeline(evidence),

        "status": alert.get("status", "New"),

        "analyst_disposition":
            alert.get("analyst_disposition"),

        "analyst_notes":
            alert.get("analyst_notes", ""),

        "created_at":
            datetime.now(timezone.utc)
            .isoformat()
            .replace("+00:00", "Z")
    }


def update_investigation(
    investigation,
    disposition=None,
    notes=None,
    status=None
):
    """
    Apply analyst decisions to an investigation.
    """

    updated = dict(investigation)

    if disposition is not None:

        if disposition not in VALID_DISPOSITIONS:
            raise ValueError(
                f"Invalid disposition: {disposition}"
            )

        updated["analyst_disposition"] = disposition


    if status is not None:

        if status not in VALID_STATUSES:
            raise ValueError(
                f"Invalid investigation status: {status}"
            )

        updated["status"] = status


    if notes is not None:
        updated["analyst_notes"] = str(notes).strip()


    updated["updated_at"] = (
        datetime.now(timezone.utc)
        .isoformat()
        .replace("+00:00", "Z")
    )

    return updated