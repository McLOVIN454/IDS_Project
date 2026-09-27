#!/usr/bin/env python3

# Entry point: runs the whole project together - capture, detection/
# notifications, threat-intel refresh, and the dashboard - instead of
# juggling separate terminals for each.
#
# Run with:
#     sudo python3 main.py
# Then open http://localhost:5000. sudo is required because the sniffer
# thread needs root to capture live packets.

import threading
import time

import database
import packet_logger
import notifier
import dashboard
import threat_intel

# How often to check for new anomalies and notify about them.
CHECK_INTERVAL_SECONDS = 60

# How often to clean out packets older than database.RETENTION_DAYS.
PRUNE_INTERVAL_SECONDS = 24 * 60 * 60


def threat_intel_loop():
    # Keeps the blocklist current in the background: once immediately (so
    # capture never starts with an empty list), then once a day after
    # that. A failed refresh just keeps using whatever's already loaded.
    while True:
        try:
            threat_intel.update_blocklist()
        except Exception as e:
            print(f"Threat intel update failed: {e}")
        time.sleep(threat_intel.REFRESH_INTERVAL_SECONDS)


def prune_loop():
    # Runs once immediately, then once a day - trims traffic.db so it
    # doesn't grow forever.
    while True:
        try:
            database.delete_old_packets()
        except Exception as e:
            print(f"Database cleanup failed: {e}")
        time.sleep(PRUNE_INTERVAL_SECONDS)


def notifier_loop():
    # Checks for anomalies and notifies, forever, with a pause between
    # checks. try/except keeps one failed check (e.g. ntfy.sh hiccup)
    # from killing this background thread.
    while True:
        try:
            notifier.check_and_notify()
        except Exception as e:
            print(f"Notifier check failed: {e}")
        time.sleep(CHECK_INTERVAL_SECONDS)


def main():
    database.init_db()

    # daemon=True so these threads die automatically when the main
    # program exits (Ctrl+C), instead of lingering in the background.
    threading.Thread(target=packet_logger.start_sniffing, daemon=True).start()
    threading.Thread(target=notifier_loop, daemon=True).start()
    threading.Thread(target=prune_loop, daemon=True).start()
    threading.Thread(target=threat_intel_loop, daemon=True).start()

    print("Dashboard running at http://localhost:5000")
    # use_reloader=False: Flask's debug auto-reloader would restart the
    # whole program in a subprocess on file changes, killing the
    # background threads started above.
    dashboard.app.run(host="0.0.0.0", port=5000, use_reloader=False)


if __name__ == "__main__":
    main()
