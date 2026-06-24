# Detection Rules

This file documents the simple detection rules used by the Local Log Analyzer.

## Rule Summary

| Rule | Severity | Pattern |
| --- | --- | --- |
| `FAILED_LOGIN` | HIGH | 3 or more `LOGIN_FAILED` events for the same user |
| `PORT_SCAN` | MEDIUM | Any `PORT_SCAN` event |
| `ACCOUNT_LOCKED` | HIGH | Any `ACCOUNT_LOCKED` event |
| `SUCCESS_AFTER_FAILURE` | MEDIUM | `LOGIN_SUCCESS` after repeated failed logins for the same user |
| `SUCCESS_FROM_NEW_IP` | HIGH | `LOGIN_SUCCESS` from a new IP after repeated failed logins |

## Rule Details

### FAILED_LOGIN

- Looks for: repeated `LOGIN_FAILED` events for the same `user=`
- Default threshold: 3
- Severity: HIGH
- MITRE ATT&CK: `T1110` Brute Force
- OWASP concept: Identification and Authentication Failures
- Analyst follow-up: check whether the user and source IP are expected
- False positive note: the user may have forgotten or mistyped a password

### PORT_SCAN

- Looks for: `PORT_SCAN` events
- Severity: MEDIUM
- MITRE ATT&CK: `T1046` Network Service Discovery
- OWASP concept: Security Misconfiguration
- Analyst follow-up: review the source IP and target systems
- False positive note: approved internal scans can be normal

### ACCOUNT_LOCKED

- Looks for: `ACCOUNT_LOCKED` events
- Severity: HIGH
- MITRE ATT&CK: `T1110` Brute Force
- OWASP concept: Security Logging and Monitoring Failures
- Analyst follow-up: confirm whether the lockout was expected
- False positive note: normal user mistakes can cause lockouts

### SUCCESS_AFTER_FAILURE

- Looks for: `LOGIN_SUCCESS` after repeated failed logins for the same user
- Severity: MEDIUM
- MITRE ATT&CK: `T1078` Valid Accounts
- OWASP concept: Identification and Authentication Failures
- Analyst follow-up: compare login time, source IP, and user behavior
- False positive note: the real user may have eventually typed the correct password

### SUCCESS_FROM_NEW_IP

- Looks for: `LOGIN_SUCCESS` from an IP that was not seen in the earlier failed-login attempts
- Severity: HIGH
- MITRE ATT&CK: `T1078` Valid Accounts
- OWASP concept: Broken Access Control and Authentication Failures
- Analyst follow-up: verify the source IP and consider password reset if unexpected
- False positive note: VPN, proxy, travel, or network changes can explain a new IP

## Important Limitations

- This is a beginner portfolio project, not a production SIEM.
- The rules use simple text matching.
- The tool does not verify real IP reputation.
- The tool does not change firewall rules or user accounts.
- Alerts should be reviewed with more context before deciding that an incident happened.

## IP Classification

The analyzer adds simple IP context for network-related alerts:

- `Internal`: private IP ranges such as `10.x.x.x`, `172.16.x.x` to `172.31.x.x`, and `192.168.x.x`
- `External test/example`: safe documentation ranges used in the sample logs, such as `198.51.100.x` and `203.0.113.x`
- `External/Unknown`: valid IPs that are not private and not documentation examples
- `Unknown`: missing or invalid IP values

This helps explain firewall review decisions, but it is not the same as real IP reputation or threat intelligence.
