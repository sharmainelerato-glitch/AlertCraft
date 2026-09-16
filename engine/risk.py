SEVERITY_SCORES = {
    "Informational": 10,
    "Low": 25,
    "Medium": 50,
    "High": 75,
    "Critical": 100
}


def calculate_risk(severity):
    return {
        "severity": severity,
        "score": SEVERITY_SCORES.get(
            severity,
            0
        )
    }