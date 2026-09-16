from pathlib import Path

import pytest

from engine.parser import (
    LogParseError,
    load_log_file,
)
from engine.detection import run_detection
from engine.investigation import (
    build_investigation,
    update_investigation,
)
from engine.replay import replay_rule


BASE_DIR = Path(__file__).resolve().parent.parent
DEMO_FILE = BASE_DIR / "data" / "demo_telemetry.json"


def load_demo():
    return load_log_file(DEMO_FILE)


def test_demo_telemetry_parses():
    events = load_demo()

    assert len(events) == 9
    assert events[0]["event_type"] == "login_failed"
    assert events[0]["username"] == "nandi.m"


def test_demo_generates_expected_rules():
    events = load_demo()
    alerts = run_detection(events)

    rule_ids = {
        alert["rule_id"]
        for alert in alerts
    }

    assert rule_ids == {
        "AC-001",
        "AC-002",
        "AC-003",
        "AC-004",
    }


def test_normal_login_does_not_create_alert():
    events = [
        {
            "event_uid": "TEST-001",
            "timestamp": "2026-09-15T09:30:10Z",
            "timestamp_dt": None,
            "host": "HR-WS04",
            "source": "windows-security",
            "event_id": 4624,
            "event_type": "login_success",
            "username": "thabo.k",
            "source_ip": "10.0.0.24",
            "destination_ip": None,
            "status": "success",
            "logon_type": 2,
            "process": None,
            "parent_process": None,
            "command_line": None,
            "raw_event": {},
        }
    ]

    alerts = run_detection(events)

    assert alerts == []


def test_removing_process_telemetry_removes_powershell_detections():
    events = load_demo()

    events = [
        event
        for event in events
        if event.get("event_type") != "process_create"
    ]

    alerts = run_detection(events)

    rule_ids = {
        alert["rule_id"]
        for alert in alerts
    }

    assert "AC-001" in rule_ids
    assert "AC-002" in rule_ids
    assert "AC-003" not in rule_ids
    assert "AC-004" not in rule_ids


def test_investigation_contains_evidence_timeline():
    events = load_demo()
    alerts = run_detection(events)

    correlated = next(
        alert
        for alert in alerts
        if alert["rule_id"] == "AC-004"
    )

    investigation = build_investigation(
        correlated
    )

    assert investigation["severity"] == "Critical"
    assert investigation["evidence_count"] == 7
    assert len(investigation["timeline"]) == 7

    assert "nandi.m" in (
        investigation["entities"]["users"]
    )

    assert "FINANCE-WS01" in (
        investigation["entities"]["hosts"]
    )


def test_valid_analyst_disposition():
    events = load_demo()
    alert = run_detection(events)[0]

    investigation = build_investigation(
        alert
    )

    updated = update_investigation(
        investigation,
        disposition="True Positive",
        status="Investigating",
        notes="Validated during controlled testing.",
    )

    assert (
        updated["analyst_disposition"]
        == "True Positive"
    )

    assert updated["status"] == "Investigating"

    assert (
        updated["analyst_notes"]
        == "Validated during controlled testing."
    )


def test_invalid_analyst_disposition_is_rejected():
    with pytest.raises(
        ValueError,
        match="Invalid disposition"
    ):
        update_investigation(
            {},
            disposition="Definitely Hacked",
        )


def test_threshold_tuning_changes_detection():
    events = load_demo()

    result = replay_rule(
        events,
        "AC-001",
        {
            "threshold": 6
        },
    )

    assert result["before"]["alert_count"] == 1
    assert result["after"]["alert_count"] == 0

    assert (
        result["comparison"]["effect"]
        == "fewer_alerts"
    )


def test_replay_does_not_modify_stored_rule():
    events = load_demo()

    result = replay_rule(
        events,
        "AC-001",
        {
            "threshold": 6
        },
    )

    assert (
        result["baseline_rule"]["threshold"]
        == 5
    )

    assert (
        result["tuned_rule"]["threshold"]
        == 6
    )

    second_result = replay_rule(
        events,
        "AC-001",
        {
            "threshold": 6
        },
    )

    assert (
        second_result["baseline_rule"]["threshold"]
        == 5
    )


def test_invalid_threshold_is_rejected():
    events = load_demo()

    with pytest.raises(
        ValueError,
        match="Threshold must be"
    ):
        replay_rule(
            events,
            "AC-001",
            {
                "threshold": 0
            },
        )

from app import app


@pytest.fixture
def client():
    app.config["TESTING"] = True

    with app.test_client() as test_client:
        yield test_client


def test_health_endpoint(client):
    response = client.get(
        "/api/health"
    )

    assert response.status_code == 200

    data = response.get_json()

    assert data["success"] is True
    assert data["service"] == "AlertCraft"
    assert data["status"] == "healthy"


def test_demo_endpoint(client):
    response = client.post(
        "/api/demo"
    )

    assert response.status_code == 200

    data = response.get_json()

    assert data["success"] is True
    assert data["source"] == "controlled_demo"
    assert data["event_count"] == 9
    assert data["alert_count"] == 4


def test_missing_upload_is_rejected(client):
    response = client.post(
        "/api/analyze"
    )

    assert response.status_code == 400

    data = response.get_json()

    assert data["success"] is False
    assert "No telemetry file" in data["error"]


def test_unsupported_file_type_is_rejected(client):
    import io

    response = client.post(
        "/api/analyze",
        data={
            "file": (
                io.BytesIO(b"test"),
                "malware.exe",
            )
        },
        content_type="multipart/form-data",
    )

    assert response.status_code == 400

    data = response.get_json()

    assert data["success"] is False
    assert "Unsupported telemetry format" in data["error"]


def test_security_headers_exist(client):
    response = client.get(
        "/api/health"
    )

    assert (
        response.headers["X-Content-Type-Options"]
        == "nosniff"
    )

    assert (
        response.headers["X-Frame-Options"]
        == "DENY"
    )

    assert (
        response.headers["Referrer-Policy"]
        == "no-referrer"
    )

    assert "Content-Security-Policy" in (
        response.headers
    )


def test_replay_rejects_invalid_threshold(client):
    events = load_demo()

    serializable_events = []

    for event in events:
        clean = dict(event)
        clean.pop("timestamp_dt", None)
        serializable_events.append(clean)

    response = client.post(
        "/api/replay",
        json={
            "events": serializable_events,
            "rule_id": "AC-001",
            "changes": {
                "threshold": 0
            },
        },
    )

    assert response.status_code == 400

    data = response.get_json()

    assert data["success"] is False
    assert "Threshold must be" in data["error"]


def test_replay_endpoint_changes_detection(client):
    events = load_demo()

    serializable_events = []

    for event in events:
        clean = dict(event)
        clean.pop("timestamp_dt", None)
        serializable_events.append(clean)

    response = client.post(
        "/api/replay",
        json={
            "events": serializable_events,
            "rule_id": "AC-001",
            "changes": {
                "threshold": 6
            },
        },
    )

    assert response.status_code == 200

    data = response.get_json()

    assert data["success"] is True

    replay = data["replay"]

    assert replay["before"]["alert_count"] == 1
    assert replay["after"]["alert_count"] == 0

def test_json_rejects_meaningless_event(tmp_path):
    telemetry_file = tmp_path / "bad.json"

    telemetry_file.write_text(
        """
        {
            "events": [
                {
                    "this is": "deliberately incomplete"
                }
            ]
        }
        """,
        encoding="utf-8",
    )

    with pytest.raises(
        LogParseError,
        match="does not contain enough security telemetry fields",
    ):
        load_log_file(telemetry_file)

def test_replay_rejects_meaningless_event(client):
    response = client.post(
        "/api/replay",
        json={
            "events": [
                {
                    "this is": "deliberately incomplete"
                }
            ],
            "rule_id": "AC-001",
            "changes": {
                "threshold": 6
            },
        },
    )

    assert response.status_code == 400

    data = response.get_json()

    assert data["success"] is False
    assert (
        "does not contain enough security telemetry fields"
        in data["error"]
    )