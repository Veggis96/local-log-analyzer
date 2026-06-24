# Changelog

## Current Version

- Reads local `.txt` and `.log` files.
- Detects failed login patterns, port scans, account lockouts, successful login after failures, and successful login from a new IP.
- Prints a terminal report.
- Saves `report.txt`, `alerts.csv`, `summary.json`, and `dashboard.html`.
- Includes a browser-only `app.html` for interactive log analysis, Mini SIEM-style normalized events, IOC summary, an incident timeline, analyst questions, remediation suggestions, event search, saved queries, data source coverage, correlation rules, selected case evidence, and local Saved Cases without a backend.
- Adds risk scoring, severity labels, recommendations, MITRE ATT&CK mapping, and OWASP learning notes.
- Includes dashboard learning sections for firewall thinking, cryptography basics, CIA triad, incident response, controls, and glossary terms.
- Includes demo scenario files for brute force, port scan, account takeover, and clean baseline activity.
- Includes a sample investigation report and standalone rule documentation.
- Includes a dedicated portfolio summary page and demo summary outputs.

## Earlier Milestones

- Started with a simple MVP: read one log file and detect 3 failed logins or `PORT_SCAN` events.
- Added report saving to `report.txt`.
- Added CSV and JSON exports.
- Added a visual HTML dashboard.
- Added incident response notes, action checklist, case status, and safe simulated countermeasures.
- Added cybersecurity learning content for portfolio presentation.
