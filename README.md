# Authentication Threat Detector

A Python security project I built to practice correlating authentication events and identifying activity that may need further investigation.

Instead of looking at each login event on its own, the detector looks at events around the same account and within a short time window. This makes it possible to spot patterns such as repeated failed logins followed by a successful login.

## What it does

The detector looks for:

* Multiple failed login attempts
* Failed logins followed by a successful login within 5 minutes
* Accounts being used from multiple IP addresses
* Login activity outside normal working hours
* Activity involving privileged accounts
* Multiple suspicious indicators occurring together
* Account timelines to make investigations easier

## How it works

The project groups authentication events by username and analyzes them together.

For example:

```text
4625  Failed login
4625  Failed login
4625  Failed login
4624  Successful login
```

If these events happen within a short period, the account is flagged for investigation.

The detector also considers other context, such as the source IP and time of the login.

## Risk Scoring

The project uses a simple scoring system to help prioritize accounts for investigation.

| Indicator                         | Points |
| --------------------------------- | -----: |
| Multiple failed logins            |    +25 |
| Failed logins followed by success |    +30 |
| Multiple source IPs               |    +20 |
| Unusual login time                |    +10 |
| Privileged account activity       |    +20 |
| Multiple indicators correlated    |    +15 |

The score is only used as an investigation aid. A high score does not automatically mean that an account has been compromised.

## Windows Events

The
