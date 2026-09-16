import os
import tempfile
from pathlib import Path

from flask import Flask, jsonify, request, render_template

from engine.parser import (
    LogParseError,
    load_log_file,
    normalize_json_event,
    serializable_event,
    validate_json_event,
)
from engine.detection import (
    load_rules,
    run_detection,
)
from engine.investigation import (
    build_investigation,
    update_investigation,
)
from engine.replay import replay_rule


# ---------------------------------------------------------
# Configuration
# ---------------------------------------------------------

BASE_DIR = Path(__file__).resolve().parent
DEMO_FILE = BASE_DIR / "data" / "demo_telemetry.json"

ALLOWED_EXTENSIONS = {
    ".json",
    ".log",
    ".txt",
}

MAX_FILE_SIZE = 5 * 1024 * 1024
MAX_REPLAY_EVENTS = 5000


# ---------------------------------------------------------
# Flask application
# ---------------------------------------------------------

app = Flask(__name__)

app.config["MAX_CONTENT_LENGTH"] = MAX_FILE_SIZE


# ---------------------------------------------------------
# Security headers
# ---------------------------------------------------------

@app.after_request
def add_security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"

    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "script-src 'self'; "
        "style-src 'self'; "
        "img-src 'self' data:; "
        "connect-src 'self'; "
        "object-src 'none'; "
        "base-uri 'self'; "
        "frame-ancestors 'none'"
    )

    return response


# ---------------------------------------------------------
# Helpers
# ---------------------------------------------------------

def error_response(message, status=400):
    return jsonify({
        "success": False,
        "error": message,
    }), status


def analyze_events(events):
    alerts = run_detection(events)

    return {
        "event_count": len(events),
        "alert_count": len(alerts),

        "events": [
            serializable_event(event)
            for event in events
        ],

        "alerts": alerts,
    }


# ---------------------------------------------------------
# Frontend
# ---------------------------------------------------------

@app.get("/")
def index():
    return render_template("index.html")


# ---------------------------------------------------------
# Health API
# ---------------------------------------------------------

@app.get("/api/health")
def health():
    return jsonify({
        "success": True,
        "service": "AlertCraft",
        "status": "healthy",
    })


# ---------------------------------------------------------
# Detection rules API
# ---------------------------------------------------------

@app.get("/api/rules")
def rules():
    try:
        detection_rules = load_rules()

        return jsonify({
            "success": True,
            "count": len(detection_rules),
            "rules": detection_rules,
        })

    except (OSError, ValueError) as error:
        return error_response(
            str(error),
            500,
        )


# ---------------------------------------------------------
# Controlled demo API
# ---------------------------------------------------------

@app.post("/api/demo")
def demo():
    try:
        events = load_log_file(
            DEMO_FILE
        )

        analysis = analyze_events(
            events
        )

        return jsonify({
            "success": True,
            "source": "controlled_demo",
            "dataset": "AlertCraft Controlled SOC Lab",
            **analysis,
        })

    except (
        LogParseError,
        OSError,
        ValueError,
    ) as error:

        return error_response(
            str(error),
            500,
        )


# ---------------------------------------------------------
# Telemetry upload API
# ---------------------------------------------------------

@app.post("/api/analyze")
def analyze():
    if "file" not in request.files:
        return error_response(
            "No telemetry file was provided."
        )

    uploaded_file = request.files["file"]

    if not uploaded_file.filename:
        return error_response(
            "No telemetry file was selected."
        )

    extension = Path(
        uploaded_file.filename
    ).suffix.lower()

    if extension not in ALLOWED_EXTENSIONS:
        return error_response(
            "Unsupported telemetry format. "
            "Use JSON, LOG or TXT."
        )

    temporary_path = None

    try:
        with tempfile.NamedTemporaryFile(
            delete=False,
            suffix=extension,
        ) as temporary_file:

            temporary_path = Path(
                temporary_file.name
            )

            uploaded_file.save(
                temporary_file
            )

        events = load_log_file(
            temporary_path
        )

        analysis = analyze_events(
            events
        )

        return jsonify({
            "success": True,
            "source": "uploaded_telemetry",
            **analysis,
        })

    except LogParseError as error:
        return error_response(
            str(error)
        )

    except (
        OSError,
        ValueError,
    ) as error:

        return error_response(
            str(error),
            500,
        )

    finally:
        if (
            temporary_path
            and temporary_path.exists()
        ):
            try:
                os.remove(
                    temporary_path
                )

            except OSError:
                pass


# ---------------------------------------------------------
# Investigation API
# ---------------------------------------------------------

@app.post("/api/investigate")
def investigate():
    payload = request.get_json(
        silent=True
    )

    if not isinstance(payload, dict):
        return error_response(
            "A JSON request body is required."
        )

    alert = payload.get(
        "alert"
    )

    if not isinstance(alert, dict):
        return error_response(
            "A valid alert object is required."
        )

    try:
        investigation = build_investigation(
            alert
        )

        if any(
            key in payload
            for key in (
                "disposition",
                "status",
                "notes",
            )
        ):

            investigation = update_investigation(
                investigation,

                disposition=payload.get(
                    "disposition"
                ),

                status=payload.get(
                    "status"
                ),

                notes=payload.get(
                    "notes"
                ),
            )

        return jsonify({
            "success": True,
            "investigation": investigation,
        })

    except ValueError as error:
        return error_response(
            str(error)
        )


# ---------------------------------------------------------
# Rule replay / tuning API
# ---------------------------------------------------------

@app.post("/api/replay")
def replay():
    payload = request.get_json(
        silent=True
    )

    if not isinstance(payload, dict):
        return error_response(
            "A JSON request body is required."
        )

    events = payload.get(
        "events"
    )

    rule_id = payload.get(
        "rule_id"
    )

    changes = payload.get(
        "changes"
    )

    if not isinstance(events, list):
        return error_response(
            "Normalized telemetry events are required."
        )

    if len(events) > MAX_REPLAY_EVENTS:
        return error_response(
            f"Replay is limited to "
            f"{MAX_REPLAY_EVENTS} events."
        )

    if not isinstance(rule_id, str):
        return error_response(
            "A valid rule_id is required."
        )

    if not isinstance(changes, dict):
        return error_response(
            "Rule tuning changes are required."
        )

    normalized_events = []

    try:
        for index, event in enumerate(
            events,
            start=1,
        ):

            if not isinstance(event, dict):
                return error_response(
                    "Every telemetry event "
                    "must be an object."
                )

            validate_json_event(
                event,
                index,
            )

            normalized_events.append(
                normalize_json_event(
                    event,
                    index,
                )
            )

        result = replay_rule(
            normalized_events,
            rule_id,
            changes,
        )

        return jsonify({
            "success": True,
            "replay": result,
        })

    except (LogParseError, ValueError) as error:
        return error_response(
            str(error)
        )


# ---------------------------------------------------------
# Error handlers
# ---------------------------------------------------------

@app.errorhandler(413)
def file_too_large(_error):
    return error_response(
        "Telemetry file exceeds the 5 MB limit.",
        413,
    )


@app.errorhandler(404)
def not_found(_error):
    return error_response(
        "Endpoint not found.",
        404,
    )


# ---------------------------------------------------------
# Local development
# ---------------------------------------------------------

if __name__ == "__main__":
    app.run(
        debug=os.getenv(
            "FLASK_DEBUG",
            "false"
        ).lower() == "true",

        host="127.0.0.1",
        port=5000,
    )