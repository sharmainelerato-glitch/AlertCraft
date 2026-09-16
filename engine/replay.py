import copy

from engine.detection import load_rules, run_detection


ALLOWED_TUNING_FIELDS = {
    "threshold",
    "window_minutes",
    "enabled"
}


def find_rule(rules, rule_id):
    for rule in rules:
        if rule.get("id") == rule_id:
            return rule

    raise ValueError(
        f"Detection rule not found: {rule_id}"
    )


def validate_tuning(changes):
    """
    Validate analyst-controlled rule changes.
    """

    if not isinstance(changes, dict):
        raise ValueError(
            "Rule tuning changes must be provided as an object."
        )

    unsupported = (
        set(changes.keys())
        - ALLOWED_TUNING_FIELDS
    )

    if unsupported:
        raise ValueError(
            "Unsupported tuning field(s): "
            + ", ".join(sorted(unsupported))
        )


    if "threshold" in changes:
        threshold = changes["threshold"]

        if (
            not isinstance(threshold, int)
            or isinstance(threshold, bool)
            or threshold < 1
            or threshold > 1000
        ):
            raise ValueError(
                "Threshold must be an integer between 1 and 1000."
            )


    if "window_minutes" in changes:
        window = changes["window_minutes"]

        if (
            not isinstance(window, int)
            or isinstance(window, bool)
            or window < 1
            or window > 1440
        ):
            raise ValueError(
                "Window must be an integer between 1 and 1440 minutes."
            )


    if "enabled" in changes:
        if not isinstance(
            changes["enabled"],
            bool
        ):
            raise ValueError(
                "Enabled must be true or false."
            )


def tune_rule(
    rules,
    rule_id,
    changes
):
    """
    Create a temporary tuned copy of a rule set.

    The original rules are not modified.
    """

    validate_tuning(changes)

    tuned_rules = copy.deepcopy(
        rules
    )

    rule = find_rule(
        tuned_rules,
        rule_id
    )

    for field, value in changes.items():
        rule[field] = value

    return tuned_rules


def alerts_for_rule(
    alerts,
    rule_id
):
    return [
        alert
        for alert in alerts
        if alert.get("rule_id") == rule_id
    ]


def replay_rule(
    events,
    rule_id,
    changes,
    rules=None
):
    """
    Run a baseline detection and a tuned detection
    against the exact same telemetry.
    """

    if rules is None:
        rules = load_rules()

    baseline_rule = copy.deepcopy(
        find_rule(
            rules,
            rule_id
        )
    )

    baseline_alerts = alerts_for_rule(
        run_detection(
            events,
            [baseline_rule]
        ),
        rule_id
    )


    tuned_rules = tune_rule(
        rules,
        rule_id,
        changes
    )

    tuned_rule = copy.deepcopy(
        find_rule(
            tuned_rules,
            rule_id
        )
    )

    tuned_alerts = alerts_for_rule(
        run_detection(
            events,
            [tuned_rule]
        ),
        rule_id
    )


    before_count = len(
        baseline_alerts
    )

    after_count = len(
        tuned_alerts
    )

    difference = (
        after_count
        - before_count
    )


    if difference < 0:
        effect = "fewer_alerts"

    elif difference > 0:
        effect = "more_alerts"

    else:
        effect = "no_count_change"


    return {
        "rule_id":
            rule_id,

        "rule_name":
            baseline_rule.get("name"),

        "baseline_rule":
            baseline_rule,

        "tuned_rule":
            tuned_rule,

        "changes":
            changes,

        "before": {
            "alert_count":
                before_count,

            "alerts":
                baseline_alerts
        },

        "after": {
            "alert_count":
                after_count,

            "alerts":
                tuned_alerts
        },

        "comparison": {
            "difference":
                difference,

            "effect":
                effect
        },

        "telemetry_event_count":
            len(events)
    }