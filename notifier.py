#!/usr/bin/env python3

# Notifier: checks for anomalies (via detector.py) and pushes an alert to
# your phone/PC via ntfy.sh whenever it finds something NEW.
#
# Setup before this works for real:
#   1. Change NTFY_TOPIC below to something unguessable - ntfy.sh topics
#      are public by default, so anyone who knows the name can read it.
#   2. Install the ntfy app (or open https://ntfy.sh/<your-topic> in a
#      browser) and subscribe to that same topic.
#
# Run any time with:
#     python3 notifier.py
# No sudo needed.

import os
import requests

import detector

NTFY_TOPIC = "change-me-to-something-unguessable"
NTFY_URL = f"https://ntfy.sh/{NTFY_TOPIC}"

# Where the timestamp of the newest already-notified anomaly is remembered,
# so re-running this doesn't re-notify about the same old anomalies.
STATE_FILE = "last_notified.txt"


def get_last_notified_ts():
    # No file yet means this is the first run ever - treat everything as new.
    if not os.path.exists(STATE_FILE):
        return 0.0
    with open(STATE_FILE, "r") as f:
        content = f.read().strip()
    return float(content) if content else 0.0


def save_last_notified_ts(ts):
    with open(STATE_FILE, "w") as f:
        f.write(str(ts))


def get_new_anomalies(all_anomalies, last_notified_ts):
    return [a for a in all_anomalies if a["ts"] > last_notified_ts]


def send_notification(message):
    requests.post(NTFY_URL, data=message.encode("utf-8"), timeout=10)


def check_and_notify():
    last_ts = get_last_notified_ts()
    all_anomalies = detector.detect_anomalies()
    new_anomalies = get_new_anomalies(all_anomalies, last_ts)

    if not new_anomalies:
        print("No new anomalies to notify about.")
        return

    for a in new_anomalies:
        message = f"[{a['type']}] {a['detail']}"
        send_notification(message)
        print(f"Sent notification: {message}")

    newest_ts = max(a["ts"] for a in new_anomalies)
    save_last_notified_ts(newest_ts)


if __name__ == "__main__":
    check_and_notify()
