import csv
from collections import defaultdict
from datetime import datetime, timedelta


# ============================================================
# AUTHENTICATION THREAT DETECTOR
# ============================================================
#
# A defensive security tool that analyzes authentication logs
# and correlates events within a time window.
#
# The detector looks for:
#
# 1. Multiple failed logins within a short period
# 2. Failed logins followed by a successful login
# 3. Authentication from multiple source IPs
# 4. Unusual login times
# 5. Suspicious activity involving privileged accounts
# 6. Multiple indicators occurring together
#
# The project uses synthetic authentication data.
# ============================================================


# ============================================================
# CONFIGURATION
# ============================================================

LOG_FILE = "auth_logs.csv"

# Number of failed attempts required for an alert.
FAILED_LOGIN_THRESHOLD = 3

# Time window used when correlating authentication events.
TIME_WINDOW = timedelta(minutes=5)

# Normal working hours.
NORMAL_START_HOUR = 8
NORMAL_END_HOUR = 18

# Accounts treated as privileged in this training dataset.
PRIVILEGED_ACCOUNTS = {
    "admin",
    "administrator",
    "david"
}


# ============================================================
# DATA STORAGE
# ============================================================

events = []

account_events = defaultdict(list)


# ============================================================
# LOAD LOG FILE
# ============================================================

try:

    with open(
        LOG_FILE,
        "r",
        newline="",
        encoding="utf-8"
    ) as file:

        reader = csv.DictReader(file)

        for row in reader:

            # Convert Event ID from text to integer.
            row["event_id"] = int(row["event_id"])

            # Convert the timestamp into a datetime object.
            row["datetime"] = datetime.strptime(
                row["time"],
                "%Y-%m-%d %H:%M:%S"
            )

            events.append(row)

except FileNotFoundError:

    print(f"[ERROR] Could not find {LOG_FILE}.")
    print("Make sure auth_logs.csv is in the same folder.")

    raise SystemExit


# ============================================================
# SORT EVENTS
# ============================================================

events.sort(
    key=lambda event: event["datetime"]
)


# ============================================================
# GROUP EVENTS BY ACCOUNT
# ============================================================

for event in events:

    username = event["username"]

    account_events[username].append(event)


# ============================================================
# HELPER FUNCTIONS
# ============================================================

def is_privileged_account(username):
    """
    Check whether an account is considered privileged.
    """

    return username.lower() in {
        account.lower()
        for account in PRIVILEGED_ACCOUNTS
    }


def is_unusual_login_time(event):
    """
    Determine whether an authentication event occurred
    outside normal working hours.
    """

    hour = event["datetime"].hour

    return (
        hour < NORMAL_START_HOUR
        or hour >= NORMAL_END_HOUR
    )


def get_recent_failures(events_for_account, success_time):
    """
    Return failed logins that occurred within the configured
    time window before a successful login.
    """

    window_start = success_time - TIME_WINDOW

    return [
        event
        for event in events_for_account
        if (
            event["event_id"] == 4625
            and window_start <= event["datetime"] < success_time
        )
    ]


# ============================================================
# DETECTION RESULTS
# ============================================================

alerts = []

risk_scores = defaultdict(int)

risk_reasons = defaultdict(list)


# ============================================================
# DETECTION 1
# MULTIPLE FAILED LOGINS
# ============================================================

for username, user_events in account_events.items():

    failures = [
        event
        for event in user_events
        if event["event_id"] == 4625
    ]

    if len(failures) >= FAILED_LOGIN_THRESHOLD:

        alerts.append({
            "username": username,
            "type": "Multiple Failed Logins",
            "time": failures[-1]["time"],
            "source_ip": failures[-1]["source_ip"],
            "details": (
                f"{len(failures)} failed login attempts"
            )
        })

        risk_scores[username] += 25

        risk_reasons[username].append(
            "multiple failed login attempts"
        )


# ============================================================
# DETECTION 2
# FAILED LOGINS FOLLOWED BY SUCCESS
# ============================================================

for username, user_events in account_events.items():

    successes = [
        event
        for event in user_events
        if event["event_id"] == 4624
    ]

    for success in successes:

        recent_failures = get_recent_failures(
            user_events,
            success["datetime"]
        )

        if len(recent_failures) >= FAILED_LOGIN_THRESHOLD:

            alerts.append({
                "username": username,
                "type": "Failed Logins Followed By Success",
                "time": success["time"],
                "source_ip": success["source_ip"],
                "details": (
                    f"{len(recent_failures)} failed logins "
                    f"within 5 minutes before successful login"
                )
            })

            risk_scores[username] += 30

            risk_reasons[username].append(
                "failed logins followed by successful login"
            )

            # Only generate this correlation alert once
            # for the account.
            break


# ============================================================
# DETECTION 3
# MULTIPLE SOURCE IP ADDRESSES
# ============================================================

for username, user_events in account_events.items():

    source_ips = {
        event["source_ip"]
        for event in user_events
    }

    if len(source_ips) > 1:

        alerts.append({
            "username": username,
            "type": "Multiple Source IPs",
            "time": user_events[-1]["time"],
            "source_ip": ", ".join(sorted(source_ips)),
            "details": (
                f"Account used from {len(source_ips)} "
                f"different IP addresses"
            )
        })

        risk_scores[username] += 20

        risk_reasons[username].append(
            "authentication from multiple source IPs"
        )


# ============================================================
# DETECTION 4
# UNUSUAL LOGIN TIME
# ============================================================

for event in events:

    if event["event_id"] not in {4624, 4625}:
        continue

    if is_unusual_login_time(event):

        username = event["username"]

        alerts.append({
            "username": username,
            "type": "Unusual Login Time",
            "time": event["time"],
            "source_ip": event["source_ip"],
            "details": "Authentication occurred outside normal hours"
        })

        risk_scores[username] += 10

        risk_reasons[username].append(
            "authentication outside normal working hours"
        )


# ============================================================
# DETECTION 5
# PRIVILEGED ACCOUNT ACTIVITY
# ============================================================

for username, user_events in account_events.items():

    if is_privileged_account(username):

        for event in user_events:

            if event["event_id"] in {4624, 4625}:

                alerts.append({
                    "username": username,
                    "type": "Privileged Account Activity",
                    "time": event["time"],
                    "source_ip": event["source_ip"],
                    "details": (
                        f"Privileged account generated "
                        f"Event ID {event['event_id']}"
                    )
                })

        # Privileged accounts receive additional
        # investigation priority.
        if username in risk_scores:

            risk_scores[username] += 20

        else:

            risk_scores[username] += 20

        risk_reasons[username].append(
            "privileged account activity"
        )


# ============================================================
# DETECTION 6
# CROSS-INDICATOR CORRELATION
# ============================================================

for username, reasons in risk_reasons.items():

    # Remove duplicate indicators.
    unique_reasons = list(dict.fromkeys(reasons))

    risk_reasons[username] = unique_reasons

    # If an account has three or more different indicators,
    # increase its risk because several signals are occurring
    # together.
    if len(unique_reasons) >= 3:

        risk_scores[username] += 15

        risk_reasons[username].append(
            "multiple suspicious indicators correlated"
        )


# ============================================================
# DETERMINE SEVERITY
# ============================================================

def get_severity(score):
    """
    Convert a numerical risk score into a severity level.
    """

    if score >= 70:
        return "HIGH"

    if score >= 40:
        return "MEDIUM"

    return "LOW"


# ============================================================
# DISPLAY HEADER
# ============================================================

print("\n" + "=" * 70)
print("AUTHENTICATION THREAT DETECTOR")
print("=" * 70)

print(f"\nTotal events analyzed: {len(events)}")
print("Correlation window: 5 minutes")
print(f"Failed login threshold: {FAILED_LOGIN_THRESHOLD}")


# ============================================================
# DISPLAY ALERTS
# ============================================================

print("\n[ALERTS]")
print("-" * 70)

if not alerts:

    print("No suspicious activity detected.")

else:

    for number, alert in enumerate(alerts, start=1):

        print(f"\nAlert #{number}")
        print(f"  Account:   {alert['username']}")
        print(f"  Type:      {alert['type']}")
        print(f"  Time:      {alert['time']}")
        print(f"  Source:    {alert['source_ip']}")
        print(f"  Details:   {alert['details']}")


# ============================================================
# DISPLAY RISK SUMMARY
# ============================================================

print("\n" + "=" * 70)
print("RISK SUMMARY")
print("=" * 70)

if not risk_scores:

    print("\nNo accounts require further investigation.")

else:

    sorted_accounts = sorted(
        risk_scores.items(),
        key=lambda item: item[1],
        reverse=True
    )

    for username, score in sorted_accounts:

        severity = get_severity(score)

        print(f"\nAccount: {username}")
        print(f"Risk Score: {score}")
        print(f"Severity: {severity}")

        print("Indicators:")

        for reason in risk_reasons[username]:

            print(f"  - {reason}")


# ============================================================
# ACCOUNT TIMELINES
# ============================================================

print("\n" + "=" * 70)
print("ACCOUNT TIMELINES")
print("=" * 70)

for username, user_events in account_events.items():

    print(f"\n{username}")
    print("-" * 40)

    for event in user_events:

        if event["event_id"] == 4624:

            result = "SUCCESS"

        elif event["event_id"] == 4625:

            result = "FAILED"

        else:

            result = event["result"].upper()

        print(
            f"{event['time']} | "
            f"{event['event_id']} | "
            f"{result} | "
            f"{event['source_ip']}"
        )


# ============================================================
# INVESTIGATION SUMMARY
# ============================================================

print("\n" + "=" * 70)
print("INVESTIGATION SUMMARY")
print("=" * 70)

high_risk_accounts = [
    username
    for username, score in risk_scores.items()
    if score >= 70
]

if not high_risk_accounts:

    print(
        "\nNo accounts reached the high-risk threshold."
    )

else:

    print(
        "\nAccounts requiring priority investigation:"
    )

    for username in high_risk_accounts:

        print(
            f"  - {username} "
            f"(Score: {risk_scores[username]})"
        )


print("\nAnalysis complete.")
