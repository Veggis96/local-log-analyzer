# Sample Investigation Report

## Executive Summary

This sample report reviews `scenario_account_takeover.txt`, a fake training log that simulates repeated failed login attempts followed by a successful login from a different IP address.

The activity should be treated as suspicious because the same user account had multiple failed login attempts and then a successful login from a new source IP. This could indicate a guessed password, credential misuse, or an account takeover attempt.

## Scope

- Log file reviewed: `scenario_account_takeover.txt`
- User account reviewed: `maria`
- Time period: `2026-06-14 10:00:01` to `2026-06-14 10:16:04`
- Tool used: Local Log Analyzer

## Timeline

| Time | Event |
| --- | --- |
| `10:00:01` | Normal successful login for `maria` from `192.168.1.30` |
| `10:15:02` | Failed login for `maria` from `203.0.113.90` |
| `10:15:11` | Failed login for `maria` from `203.0.113.90` |
| `10:15:20` | Failed login for `maria` from `203.0.113.90` |
| `10:16:04` | Successful login for `maria` from new IP `198.51.100.91` |

## Alerts Found

| Alert type | Severity | Reason |
| --- | --- | --- |
| `FAILED_LOGIN` | HIGH | The user `maria` had 3 failed login attempts |
| `SUCCESS_AFTER_FAILURE` | MEDIUM | Login succeeded after repeated failures |
| `SUCCESS_FROM_NEW_IP` | HIGH | Login succeeded from an IP different from the failed-login IP |

## MITRE ATT&CK Mapping

| Alert type | Technique |
| --- | --- |
| `FAILED_LOGIN` | `T1110` Brute Force |
| `SUCCESS_AFTER_FAILURE` | `T1078` Valid Accounts |
| `SUCCESS_FROM_NEW_IP` | `T1078` Valid Accounts |

## OWASP Mapping

| Alert type | OWASP concept |
| --- | --- |
| `FAILED_LOGIN` | Identification and Authentication Failures |
| `SUCCESS_AFTER_FAILURE` | Identification and Authentication Failures |
| `SUCCESS_FROM_NEW_IP` | Broken Access Control and Authentication Failures |

## Evidence

```text
2026-06-14 10:15:02 LOGIN_FAILED user=maria ip=203.0.113.90
2026-06-14 10:15:11 LOGIN_FAILED user=maria ip=203.0.113.90
2026-06-14 10:15:20 LOGIN_FAILED user=maria ip=203.0.113.90
2026-06-14 10:16:04 LOGIN_SUCCESS user=maria ip=198.51.100.91
```

## Analyst Conclusion

This activity is suspicious because the account had repeated failed logins and then a successful login from a new IP address. A real analyst should verify whether the successful login was expected.

This scenario does not prove compromise by itself. It is a signal that should be reviewed with more context, such as user location, VPN use, MFA logs, device history, and helpdesk tickets.

## Recommended Next Steps

- Contact or verify with the account owner.
- Check whether `198.51.100.91` is expected, trusted, or related to VPN use.
- Review MFA logs if available.
- Consider a password reset if the login is not expected.
- Document the investigation result and close the case only after validation.

## False Positive Notes

Possible non-malicious explanations:

- The user mistyped the password several times.
- The user connected through a VPN or proxy.
- The user changed networks or locations.
- The log source may not show all context.

## Lessons Learned

- Repeated failures followed by success should be reviewed.
- A new source IP after failures increases suspicion.
- Good investigation requires both alert data and context.
- Clear documentation is part of cybersecurity work, not just detection.
