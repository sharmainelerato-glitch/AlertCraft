# AlertCraft

AlertCraft is a detection engineering and investigation lab I built to practise how security alerts are created, investigated and improved.

Instead of only displaying alerts, the project lets me work through the detection process from telemetry to investigation and rule tuning.

## What it does

AlertCraft can:

- Analyse uploaded JSON, LOG and TXT telemetry
- Detect suspicious authentication and PowerShell activity
- Correlate related security events
- Show the evidence behind each alert
- Map detections to MITRE ATT&CK techniques
- Build an investigation timeline
- Record analyst notes and dispositions
- Tune detection rules
- Replay the same telemetry to see how a rule change affects alerts
- Generate an investigation report that can be printed or saved as PDF

## Detection lab

The included demo contains controlled security telemetry representing failed authentication attempts, a successful login and suspicious PowerShell activity.

The current detection rules include:

- Authentication Failure Burst
- Failed Authentication Followed by Success
- Encoded PowerShell Execution
- Suspicious Authentication Followed by PowerShell

The demo data is synthetic so the detection workflow can be tested safely.

## Detection replay

One of the main parts of AlertCraft is the replay feature.

I can adjust a detection rule and test it against the same telemetry again. AlertCraft then compares the alerts before and after the change.

This helps me practise detection tuning and understand how changing a rule affects what gets detected.

## Tech used

- Python
- Flask
- JavaScript
- HTML
- CSS
- Pytest
- MITRE ATT&CK

## Testing

The project includes automated tests for the parser, detection rules, investigations, replay functionality and API behaviour.

To run the tests:

```bash
python -m pytest -q
```

The current test suite contains 19 automated tests.

## Why I built it

I built AlertCraft to improve my practical skills in detection engineering, SOC investigations and alert tuning.

I wanted a project where I could work with telemetry, understand why an alert fired, investigate the evidence and then test how changes to a detection rule affect the result.

## Important note

AlertCraft is a learning and portfolio project. It is not a production SIEM, and the included demo telemetry is synthetic.