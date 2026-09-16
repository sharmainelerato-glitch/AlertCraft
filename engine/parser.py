import json
import re
from datetime import datetime, timezone
from pathlib import Path


class LogParseError(Exception):
    """Raised when AlertCraft cannot safely parse a telemetry file."""
    pass


def parse_iso_timestamp(value):
    if not value:
        return None

    try:
        return datetime.fromisoformat(
            str(value).replace("Z", "+00:00")
        )
    except (ValueError, TypeError):
        return None

def validate_json_event(event, index):
    """
    Validate that a JSON object contains enough structure
    to be treated as security telemetry.

    AlertCraft accepts flexible event schemas, but an object
    must contain at least one meaningful event identifier and
    one piece of security context.
    """
    if not isinstance(event, dict):
        raise LogParseError(
            f"Event {index} must be a JSON object."
        )

    identity_fields = (
        "event_id",
        "event_type",
        "timestamp",
    )

    context_fields = (
        "host",
        "username",
        "source_ip",
        "destination_ip",
        "status",
        "process",
        "parent_process",
        "command_line",
        "logon_type",
    )

    has_identity = any(
        event.get(field) not in (None, "")
        for field in identity_fields
    )

    has_context = any(
        event.get(field) not in (None, "")
        for field in context_fields
    )

    if not has_identity or not has_context:
        raise LogParseError(
            f"Event {index} does not contain enough "
            "security telemetry fields to analyze."
        )

def normalize_json_event(event, index):
    """
    Convert a JSON security event into AlertCraft's common event schema.
    """

    timestamp = event.get("timestamp")

    return {
        "event_uid": f"EVT-{index:05d}",
        "timestamp": timestamp,
        "timestamp_dt": parse_iso_timestamp(timestamp),

        "host": event.get("host") or "unknown",
        "source": event.get("source") or "json",
        "event_id": event.get("event_id"),
        "event_type": event.get("event_type") or "unknown",

        "username": event.get("username"),
        "source_ip": event.get("source_ip"),
        "destination_ip": event.get("destination_ip"),

        "status": event.get("status"),
        "logon_type": event.get("logon_type"),

        "process": event.get("process"),
        "parent_process": event.get("parent_process"),
        "command_line": event.get("command_line"),

        "raw_event": event
    }


def parse_json_file(path):
    """
    Parse JSON telemetry.

    Supported structures:

    [
        {...},
        {...}
    ]

    or:

    {
        "events": [
            {...},
            {...}
        ]
    }
    """
    try:
        with open(path, "r", encoding="utf-8") as file:
            data = json.load(file)

    except json.JSONDecodeError as error:
        raise LogParseError(
            f"Invalid JSON: {error.msg}"
        ) from error

    except OSError as error:
        raise LogParseError(
            f"Unable to read telemetry file: {error}"
        ) from error

    if isinstance(data, dict) and "events" in data:
        data = data["events"]

    elif isinstance(data, dict):
        data = [data]

    if not isinstance(data, list):
        raise LogParseError(
            "JSON telemetry must contain an event object "
            "or a list of event objects."
        )

    events = []

    for index, item in enumerate(data, start=1):
        validate_json_event(
            item,
            index
        )

        events.append(
            normalize_json_event(
                item,
                index
            )
        )

    if not events:
        raise LogParseError(
            "No usable security events were found in the JSON file."
        )

    return events

FAILED_SSH_PATTERN = re.compile(
    r"Failed password for "
    r"(?:(?:invalid user)\s+)?"
    r"(?P<username>\S+) "
    r"from "
    r"(?P<ip>\d{1,3}(?:\.\d{1,3}){3})",
    re.IGNORECASE
)


SUCCESS_SSH_PATTERN = re.compile(
    r"Accepted "
    r"(?:password|publickey) "
    r"for "
    r"(?P<username>\S+) "
    r"from "
    r"(?P<ip>\d{1,3}(?:\.\d{1,3}){3})",
    re.IGNORECASE
)


LINUX_PREFIX_PATTERN = re.compile(
    r"^(?P<month>[A-Z][a-z]{2})\s+"
    r"(?P<day>\d{1,2})\s+"
    r"(?P<time>\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)"
)


def parse_linux_timestamp(line):
    """
    auth.log normally does not include the year.

    For a lab parser, use the current UTC year while preserving
    the month/day/time from the log.
    """

    match = LINUX_PREFIX_PATTERN.search(line)

    if not match:
        return None, None


    current_year = datetime.now(
        timezone.utc
    ).year


    value = (
        f"{current_year} "
        f"{match.group('month')} "
        f"{match.group('day')} "
        f"{match.group('time')}"
    )


    try:
        parsed = datetime.strptime(
            value,
            "%Y %b %d %H:%M:%S"
        ).replace(
            tzinfo=timezone.utc
        )

        return (
            parsed.isoformat()
            .replace("+00:00", "Z"),
            parsed
        )

    except ValueError:
        return None, None


def parse_linux_auth_file(path):
    """
    Parse common SSH authentication events from
    Linux auth.log-style telemetry.
    """

    events = []


    try:
        with open(
            path,
            "r",
            encoding="utf-8",
            errors="replace"
        ) as file:

            for line_number, line in enumerate(
                file,
                start=1
            ):

                failed = FAILED_SSH_PATTERN.search(
                    line
                )

                success = SUCCESS_SSH_PATTERN.search(
                    line
                )


                if not failed and not success:
                    continue


                timestamp, timestamp_dt = (
                    parse_linux_timestamp(line)
                )


                prefix = LINUX_PREFIX_PATTERN.search(
                    line
                )

                host = (
                    prefix.group("host")
                    if prefix
                    else "linux-host"
                )


                match = failed or success

                event_type = (
                    "login_failed"
                    if failed
                    else "login_success"
                )

                status = (
                    "failure"
                    if failed
                    else "success"
                )


                events.append({
                    "event_uid":
                        f"EVT-{len(events) + 1:05d}",

                    "timestamp":
                        timestamp,

                    "timestamp_dt":
                        timestamp_dt,

                    "host":
                        host,

                    "source":
                        "linux-auth",

                    "event_id":
                        "SSH-AUTH",

                    "event_type":
                        event_type,

                    "username":
                        match.group("username"),

                    "source_ip":
                        match.group("ip"),

                    "destination_ip":
                        None,

                    "status":
                        status,

                    "logon_type":
                        "ssh",

                    "process":
                        "sshd",

                    "parent_process":
                        None,

                    "command_line":
                        None,

                    "line_number":
                        line_number,

                    "raw_event":
                        line.strip()
                })


    except OSError as error:
        raise LogParseError(
            f"Unable to read telemetry file: {error}"
        ) from error


    if not events:
        raise LogParseError(
            "No supported SSH authentication events "
            "were found in this log."
        )


    return events


def load_log_file(path):
    """
    Automatically select the correct parser based on file extension.
    """

    path = Path(path)

    extension = path.suffix.lower()


    if extension == ".json":
        return parse_json_file(path)


    if extension in {
        ".log",
        ".txt"
    }:
        return parse_linux_auth_file(path)


    raise LogParseError(
        "Unsupported telemetry format. "
        "AlertCraft currently accepts JSON, LOG and TXT files."
    )


def serializable_event(event):
    """
    Remove Python-only values before returning an event through the API.
    """

    clean = dict(event)

    clean.pop(
        "timestamp_dt",
        None
    )

    return clean