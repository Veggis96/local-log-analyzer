# Investigation Guide

Use this guide when reviewing alerts from the Local Log Analyzer.

## First Triage

- Start with `HIGH` alerts.
- Check the most suspicious user.
- Check the most active source IP.
- Review the first and last timestamp to understand the time window.

## Failed Login Questions

- Which user had repeated failed logins?
- Were the failed logins close together in time?
- Is this user expected to log in from this IP address?
- Did the same user later log in successfully?

## Port Scan Questions

- Which source IP created the port scan events?
- Did the source IP scan more than one target?
- Is the source IP internal or external?
- Should this source IP be reviewed or blocked in a real environment?

## Account Lockout Questions

- Which account was locked?
- Did the lockout happen after repeated failed logins?
- Is the account important, such as `admin` or `backup`?
- Should the user confirm whether the lockout was expected?

## Successful Login After Failures

- Which user logged in successfully?
- How many failed attempts happened before the success?
- Did the successful login come from the same IP address?
- Should the password be reset in a real environment?

## Successful Login From A New IP

- Which user logged in successfully from the new IP?
- What IP addresses were used during the failed attempts?
- Is the successful login IP expected for this user?
- Should this be treated as higher priority than a normal success after failures?

## When To Escalate

Escalate the case if:

- There are multiple `HIGH` alerts.
- A successful login happens after repeated failures.
- A successful login happens from a new IP after repeated failures.
- A sensitive account is locked or targeted.
- A source IP appears in several suspicious events.

## What To Document

- Log file name
- Time window
- Alert types found
- Users involved
- Source IPs involved
- Actions taken or recommended
