# AlertCraft

AlertCraft is a detection engineering and investigation lab I built to practise how security alerts are created, investigated and improved.

Instead of only displaying alerts, the project lets me work through the detection process from telemetry to investigation and rule tuning.

**Live demo:** https://alertcraft.onrender.com

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

## Investigation workflow

When an alert is generated, I can open it and review the events that caused the detection.

The investigation view lets me:

- Review the alert evidence
- Follow the event timeline
- See the related MITRE ATT&CK techniques
- Set an investigation status
- Record a disposition such as True Positive or False Positive
- Add analyst notes

This gives me a way to practise both detection and investigation instead of stopping when an alert fires.

## Reports

AlertCraft can build an investigation report from the current analysis.

The report can include:

- Analysis summary
- Detected findings
- MITRE ATT&CK mappings
- Investigation information
- Analyst notes and disposition
- Detection replay results

Reports can be printed or saved as PDF from the browser.

## Tech used

- Python
- Flask
- JavaScript
- HTML
- CSS
- Pytest
- MITRE ATT&CK
- Gunicorn

## Testing

The project includes automated tests for the parser, detection rules, investigations, replay functionality, telemetry validation and API behaviour.

To run the tests:

```bash
python -m pytest -q