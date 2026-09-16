import json
import uuid

from datetime import timedelta
from pathlib import Path

from engine.parser import serializable_event
from engine.risk import calculate_risk


BASE_DIR = Path(__file__).resolve().parent.parent
RULES_FILE = BASE_DIR / "data" / "rules.json"


def load_rules():
    with open(
        RULES_FILE,
        "r",
        encoding="utf-8"
    ) as file:
        return json.load(file)


def create_alert(
    rule,
    title,
    description,
    evidence,
    host=None,
    username=None,
    source_ip=None,
    reason=None
):
    risk = calculate_risk(
        rule["severity"]
    )

    return {
        "alert_id":
            f"ALT-{uuid.uuid4().hex[:8].upper()}",

        "rule_id":
            rule["id"],

        "rule_name":
            rule["name"],

        "title":
            title,

        "description":
            description,

        "reason":
            reason,

        "severity":
            risk["severity"],

        "risk_score":
            risk["score"],

        "host":
            host,

        "username":
            username,

        "source_ip":
            source_ip,

        "mitre":
            rule["mitre"],

        "evidence_count":
            len(evidence),

        "evidence": [
            serializable_event(event)
            for event in evidence
        ],

        "status":
            "New",

        "analyst_disposition":
            None,

        "analyst_notes":
            ""
    }


def event_time(event):
    return event.get(
        "timestamp_dt"
    )


def within_window(
    earlier,
    later,
    minutes
):
    earlier_time = event_time(
        earlier
    )

    later_time = event_time(
        later
    )

    if (
        earlier_time is None
        or later_time is None
    ):
        return True

    difference = (
        later_time
        - earlier_time
    )

    return (
        timedelta(0)
        <= difference
        <= timedelta(minutes=minutes)
    )


def detect_failed_login_burst(
    events,
    rule
):
    alerts = []

    threshold = rule.get(
        "threshold",
        5
    )

    window_minutes = rule.get(
        "window_minutes",
        5
    )


    failures = [
        event
        for event in events
        if event.get("event_type")
        == "login_failed"
    ]


    groups = {}

    for event in failures:

        key = (
            event.get("username"),
            event.get("source_ip"),
            event.get("host")
        )

        groups.setdefault(
            key,
            []
        ).append(event)


    for (
        username,
        source_ip,
        host
    ), group in groups.items():

        group = sorted(
            group,
            key=lambda item:
                item.get("timestamp_dt")
                or item.get("event_uid")
        )


        for start_index in range(
            len(group)
        ):

            window = [
                group[start_index]
            ]


            for candidate in group[
                start_index + 1:
            ]:

                if within_window(
                    group[start_index],
                    candidate,
                    window_minutes
                ):
                    window.append(
                        candidate
                    )


            if len(window) >= threshold:

                evidence = window[
                    :threshold
                ]

                alerts.append(
                    create_alert(
                        rule=rule,

                        title=(
                            "Authentication "
                            "failure burst"
                        ),

                        description=(
                            f"{len(evidence)} failed "
                            "authentication attempts "
                            f"occurred within "
                            f"{window_minutes} minutes."
                        ),

                        evidence=evidence,

                        host=host,
                        username=username,
                        source_ip=source_ip,

                        reason=(
                            f"Rule threshold met: "
                            f"{len(evidence)} failures "
                            f">= {threshold} required."
                        )
                    )
                )

                break


    return alerts


def detect_failed_then_success(
    events,
    rule
):
    alerts = []

    threshold = rule.get(
        "threshold",
        5
    )

    window_minutes = rule.get(
        "window_minutes",
        5
    )


    successes = [
        event
        for event in events
        if event.get("event_type")
        == "login_success"
    ]


    for success in successes:

        username = success.get(
            "username"
        )

        source_ip = success.get(
            "source_ip"
        )

        host = success.get(
            "host"
        )


        matching_failures = [
            event
            for event in events
            if (
                event.get("event_type")
                == "login_failed"

                and event.get("username")
                == username

                and event.get("source_ip")
                == source_ip

                and event.get("host")
                == host

                and within_window(
                    event,
                    success,
                    window_minutes
                )
            )
        ]


        if len(
            matching_failures
        ) >= threshold:

            evidence = (
                matching_failures
                + [success]
            )

            alerts.append(
                create_alert(
                    rule=rule,

                    title=(
                        "Failed authentication "
                        "followed by success"
                    ),

                    description=(
                        f"{len(matching_failures)} "
                        "failed authentication attempts "
                        "were followed by a successful "
                        "login from the same source."
                    ),

                    evidence=evidence,

                    host=host,
                    username=username,
                    source_ip=source_ip,

                    reason=(
                        "Authentication failures "
                        "and subsequent success share "
                        "the same user, source IP and host."
                    )
                )
            )


    return alerts


def detect_encoded_powershell(
    events,
    rule
):
    alerts = []


    indicators = [
        "-enc",
        "-encodedcommand",
        "-encoded"
    ]


    for event in events:

        if (
            event.get("event_type")
            != "process_create"
        ):
            continue


        process = (
            event.get("process")
            or ""
        ).lower()


        command_line = (
            event.get("command_line")
            or ""
        ).lower()


        matched = [
            indicator
            for indicator in indicators
            if indicator
            in command_line
        ]


        if (
            "powershell" in process
            and matched
        ):

            alerts.append(
                create_alert(
                    rule=rule,

                    title=(
                        "Encoded PowerShell "
                        "execution"
                    ),

                    description=(
                        "PowerShell executed with "
                        "an encoded command argument."
                    ),

                    evidence=[
                        event
                    ],

                    host=event.get(
                        "host"
                    ),

                    username=event.get(
                        "username"
                    ),

                    source_ip=event.get(
                        "source_ip"
                    ),

                    reason=(
                        "PowerShell process contained "
                        f"encoded argument indicator: "
                        f"{matched[0]}"
                    )
                )
            )


    return alerts


def detect_auth_then_powershell(
    events,
    rule
):
    alerts = []

    threshold = rule.get(
        "threshold",
        5
    )

    window_minutes = rule.get(
        "window_minutes",
        10
    )


    powershell_events = [
        event
        for event in events
        if (
            event.get("event_type")
            == "process_create"

            and "powershell"
            in (
                event.get("process")
                or ""
            ).lower()
        )
    ]


    for powershell in powershell_events:

        host = powershell.get(
            "host"
        )

        username = powershell.get(
            "username"
        )


        successful_logins = [
            event
            for event in events
            if (
                event.get("event_type")
                == "login_success"

                and event.get("host")
                == host

                and event.get("username")
                == username

                and within_window(
                    event,
                    powershell,
                    window_minutes
                )
            )
        ]


        for success in successful_logins:

            source_ip = success.get(
                "source_ip"
            )


            failures = [
                event
                for event in events
                if (
                    event.get("event_type")
                    == "login_failed"

                    and event.get("host")
                    == host

                    and event.get("username")
                    == username

                    and event.get("source_ip")
                    == source_ip

                    and within_window(
                        event,
                        success,
                        window_minutes
                    )
                )
            ]


            if len(
                failures
            ) >= threshold:

                evidence = (
                    failures
                    + [
                        success,
                        powershell
                    ]
                )


                alerts.append(
                    create_alert(
                        rule=rule,

                        title=(
                            "Suspicious authentication "
                            "followed by PowerShell"
                        ),

                        description=(
                            f"{len(failures)} failed "
                            "logins were followed by a "
                            "successful login and then "
                            "PowerShell execution on "
                            "the same host."
                        ),

                        evidence=evidence,

                        host=host,
                        username=username,
                        source_ip=source_ip,

                        reason=(
                            "AlertCraft correlated "
                            "authentication failures, "
                            "successful authentication "
                            "and subsequent PowerShell "
                            "execution."
                        )
                    )
                )

                break


    return alerts


DETECTORS = {
    "failed_login_burst":
        detect_failed_login_burst,

    "failed_then_success":
        detect_failed_then_success,

    "encoded_powershell":
        detect_encoded_powershell,

    "auth_then_powershell":
        detect_auth_then_powershell
}


def run_detection(
    events,
    rules=None
):
    if rules is None:
        rules = load_rules()


    alerts = []


    for rule in rules:

        if not rule.get(
            "enabled",
            True
        ):
            continue


        detector = DETECTORS.get(
            rule.get("type")
        )


        if detector is None:
            continue


        generated = detector(
            events,
            rule
        )


        alerts.extend(
            generated
        )


    return alerts