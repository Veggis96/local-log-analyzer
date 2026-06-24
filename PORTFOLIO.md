# Portfolio Project Summary

## Project Name

Local Log Analyzer

## Short Pitch

Local Log Analyzer is a beginner-friendly Python cybersecurity project that reads local log files, detects suspicious login and network activity, and produces analyst-style reports and dashboards.

The project demonstrates practical security thinking: detection rules, alert severity, risk scoring, MITRE ATT&CK mapping, OWASP awareness, firewall review, cryptography basics, and incident response documentation.

## Problem It Solves

Security teams review logs to find suspicious behavior. This project simulates that workflow with simple fake logs and beginner-readable detection logic.

It can detect:

- Repeated failed logins
- Port scan events
- Account lockouts
- Successful login after repeated failures
- Successful login from a new IP after repeated failures

## Skills Demonstrated

### Python

- File reading
- String parsing
- Dictionaries and lists
- Functions
- Command-line arguments
- CSV, JSON, text, and HTML output
- Simple test functions

### Cybersecurity

- Log analysis
- Detection rules
- Brute-force detection
- Port scan review
- Account takeover warning signs
- Risk scoring
- MITRE ATT&CK mapping
- OWASP Top 10 awareness
- CIA triad
- Firewall thinking
- Cryptography basics
- Incident response documentation

### Communication

- Analyst-style reports
- Rule documentation
- Scenario-based testing
- Portfolio screenshots
- Interview talking points

## Demo Flow

1. Open the browser app:

```text
app.html
```

2. Click the `Account takeover` demo scenario.

3. Review the risk score, IOC summary, incident timeline, analyst questions, remediation suggestions, alert table, correlation rules, data source coverage, normalized events, MITRE ATT&CK mapping, Saved Cases, Firewall Review, and Learning Notes.

4. Select important alert or event rows as evidence, then create a saved case report.

5. Optional: run all scenarios from the terminal:

```bash
python run_demo.py
```

6. Open:

```text
demo_summary.html
```

7. Run the account takeover scenario with Python:

```bash
python analyzer.py --scenario account_takeover
```

8. Open:

```text
dashboard.html
```

9. Review:

- Risk level
- Alerts table
- MITRE ATT&CK mapping
- OWASP Top 10 Learning Map
- Firewall Review
- Incident Response Summary
- Case Status

## Best Screenshots To Capture

- `demo_summary.html` showing all demo scenarios
- `app.html` showing Mini SIEM-style IOC summary, incident timeline, analyst questions, remediation suggestions, event search, saved queries, data source coverage, selected evidence, correlation rules, and Saved Cases workflow
- `dashboard.html` top overview with risk score
- Dashboard alert table with MITRE ATT&CK mapping
- OWASP Top 10 Learning Map
- Security Controls Matrix
- Incident Response Summary and Case Status

## Strongest Scenario

The strongest demo scenario is:

```bash
python analyzer.py --scenario account_takeover
```

Why it is useful:

- It shows failed logins.
- It shows a successful login after failures.
- It shows a successful login from a new IP.
- It creates both `T1110` Brute Force and `T1078` Valid Accounts learning connections.
- It shows normalized event search, which is a basic SIEM concept.
- It supports a realistic analyst investigation report.

## How I Would Explain It In An Interview

"I built a Python log analyzer that reads fake local log files and detects suspicious login and network behavior. I started with a small MVP, then added alert severity, risk scoring, CSV and JSON output, a dashboard, MITRE ATT&CK mapping, OWASP learning notes, demo scenarios, and a sample investigation report. The project helped me practice both Python fundamentals and cybersecurity analyst thinking."

## Limitations

- This is not a production SIEM.
- It uses simple text matching.
- It does not connect to real systems.
- It does not block IPs or change firewall rules.
- It does not verify real threat intelligence.

## Future Improvements

- Add more event types.
- Add date filtering.
- Add internal vs external IP classification.
- Add more scenario files.
- Add dashboard screenshots to the README.
- Add a small configuration file for thresholds.
