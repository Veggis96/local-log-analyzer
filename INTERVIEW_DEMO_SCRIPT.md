# Interview Demo Script

This is a short guide for explaining the Local Log Analyzer project in an interview or portfolio walkthrough.

## 30-Second Pitch

Local Log Analyzer is a beginner cybersecurity portfolio project that analyzes sample login and network logs. It detects suspicious patterns like repeated failed logins, port scans, account lockouts, and successful logins after failures. I built both a Python command-line analyzer and a browser-based Mini SIEM-style app with IOC summary, timeline, analyst questions, MITRE ATT&CK mapping, saved cases, and remediation suggestions.

## 2-Minute Live Demo

1. Open the live app:

```text
https://veggis96.github.io/local-log-analyzer/app.html
```

2. Click `Account takeover`.

What to say:

```text
This scenario shows failed login attempts followed by a successful login from a different source IP.
```

3. Point out the risk score and alert count.

What to say:

```text
The app gives the scenario a high risk rating because the login pattern may indicate account takeover.
```

4. Show the IOC Summary.

What to say:

```text
The IOC section summarizes users, source IPs, target IPs, and event types so an analyst can quickly identify what matters.
```

5. Show the Incident Timeline.

What to say:

```text
The timeline helps explain the order of events, which is important for incident investigation.
```

6. Show Analyst Questions.

What to say:

```text
These questions guide a beginner analyst through what to validate next, such as affected users, unusual IPs, and escalation.
```

7. Show Remediation Suggestions.

What to say:

```text
The remediation section suggests safe next actions, like validating the login with the user, checking MFA, and documenting the case.
```

8. Select a few evidence rows and create a saved case.

What to say:

```text
The saved case workflow shows basic incident response documentation by connecting alerts and raw event evidence.
```

## Common Interview Questions

### What problem does this project solve?

It helps a beginner analyst practice reading logs, identifying suspicious activity, and turning alerts into a simple investigation report.

### Is this a real SIEM?

No. It is not a production SIEM. It is a learning project that demonstrates SIEM-like concepts such as parsing, alerting, event normalization, timeline review, IOC summary, and case notes.

### Why did you use sample logs?

Sample logs are safe for a public portfolio. They let me demonstrate cybersecurity concepts without exposing real company or personal data.

### What cybersecurity concepts does it show?

It shows log analysis, brute force detection, port scan detection, MITRE ATT&CK mapping, OWASP authentication awareness, firewall thinking, incident response, evidence handling, and remediation planning.

### What would you improve next?

I would add support for more log formats, export saved cases as JSON, add more MITRE mappings, and later experiment with syslog-style ingestion.

### What did you learn?

I learned how to parse logs with Python, structure detection rules, create readable reports, map alerts to security concepts, and explain findings in a way an analyst could use.

## Short Closing Statement

```text
This project started as a simple Python log analyzer and grew into a small Mini SIEM-style portfolio app. I kept the code beginner-friendly, but added realistic analyst workflow features like IOC review, timeline, case evidence, and remediation suggestions.
```
