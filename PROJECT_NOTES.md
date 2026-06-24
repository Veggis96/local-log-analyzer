# Project Notes

## Project Summary

Local Log Analyzer is a beginner Python cybersecurity project.

It reads local text log files, looks for suspicious login and network activity, prints a report in the terminal, and creates simple output files for review.

## What The Project Detects

- Repeated failed logins from the same user
- Port scan events
- Account lockout events
- Successful logins after repeated failed logins
- Successful logins from a new IP after repeated failed logins

## Why These Events Matter

Repeated failed logins can mean someone is guessing a password.

Port scans can mean someone is checking which network services are open.

Account lockouts can happen after too many failed login attempts.

A successful login after repeated failures should be reviewed because the password may have been guessed.

A successful login from a different IP after repeated failures is more suspicious because it may show that access moved to a new location.

## What I Practiced

- Reading files with Python
- Splitting log lines into useful pieces
- Counting events with dictionaries
- Creating alerts from simple rules
- Comparing failed-login IP addresses with later successful-login IP addresses
- Saving reports as text, CSV, JSON, and HTML
- Writing simple tests
- Building a basic security dashboard without frameworks
- Summarizing alerts into a simple incident response note
- Mapping simple detections to MITRE ATT&CK-style techniques
- Filtering alerts by minimum severity
- Writing investigation questions for alert review

## Current Limitations

- The project only understands a few fake log formats.
- The rules are simple and do not use advanced threat detection.
- The MITRE ATT&CK mapping is simplified for learning.
- Severity filtering only filters generated alert outputs, not the raw log data.
- The dashboard is a static HTML file.
- Countermeasures are simulated for learning and do not affect real systems.
- The sample data is for learning, not from a real production system.

## Future Improvements

- Support more event types, such as unusual login times or unknown usernames
- Add clearer risk scoring rules
- Add more realistic sample logs
- Add a search box to the dashboard
- Add a simple way to compare two log files

## Portfolio Talking Point

This project shows that I can take raw log text, extract useful security signals, create alerts, and present the results in a readable report and dashboard.

It also shows a simple incident response workflow: review high-priority alerts, plan safe countermeasures, and create a short response note.

The project also connects simple alert types to well-known MITRE ATT&CK technique names, which helps explain detections in a more professional way.
