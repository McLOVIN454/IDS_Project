#!/usr/bin/env python3

# Detector: scans packets/threat-intel hits saved by packet_logger.py and
# flags anomalies - traffic that doesn't match what's normal so far.
#
# Four things get flagged:
#   1. NEW_DEVICE - the first time a MAC address ever shows up.
#   2. SSH_CONNECTION - flagged once per session (packets between the same
#      two machines close together in time count as one session), not
#      once per packet.
#   3. NEW_PORT - a port a specific device hasn't talked on before, once
#      that device's own 7-day learning period has passed.
#   4. MALICIOUS_IP - traffic involving an IP on the threat-intel blocklist
#      (checked by packet_logger.py at capture time; this just reads back
#      what was already found).
#
# Keeps its state (which devices/ports/sessions it already knows about,
# and how far through the database it's already read) in memory between
# calls, so each call only processes rows saved SINCE the last call instead
# of replaying the entire packet history every time. That full replay was
# fine early on, but became the dashboard's main bottleneck once
# traffic.db grew into the millions of rows - every page load (and every
# 5-second auto-refresh) was re-scanning the whole thing from scratch.
#
# Run any time with:
#     python3 detector.py
# No sudo needed. The first run after a restart still has to process
# whatever's already in the database, so it can take a while on a large
# existing traffic.db - every run after that is fast, since it only looks
# at what's new.

import threading

import database

LEARNING_PERIOD_DAYS = 7
LEARNING_PERIOD_SECONDS = LEARNING_PERIOD_DAYS * 24 * 60 * 60

SSH_PORT = 22
SSH_SESSION_GAP_SECONDS = 5 * 60

DASHBOARD_PORT = 5000

# Shared state carried between calls. Guarded by _lock since the
# dashboard (handling a web request) and the notifier (a background
# thread) can both call detect_anomalies() at the same time.
_lock = threading.Lock()
_first_seen = {}      # mac -> timestamp that device was first ever seen
_known_ports = {}      # mac -> set of ports seen so far for that device
_last_ssh_ts = {}       # (ip, ip) pair -> timestamp of the most recent SSH packet
_last_packet_id = 0     # highest packets.id already processed
_last_flag_id = 0       # highest flagged_ips.id already processed
_anomalies = []          # every anomaly found so far, oldest first
_caught_up = False       # becomes True after startup skips past old history


def _process_packet_row(row):
    # Runs the three packet-based checks against one row and appends any
    # anomaly found straight onto the shared _anomalies list.
    row_id, ts, mac, src_ip, dst_ip, proto, port, size, dns_query = row

    if mac not in _first_seen:
        _first_seen[mac] = ts
        _known_ports[mac] = set()
        _anomalies.append({
            "type": "NEW_DEVICE",
            "ts": ts,
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "detail": f"New device seen: {mac} ({src_ip})",
        })

    learning_period_over = (ts - _first_seen[mac]) >= LEARNING_PERIOD_SECONDS

    if port == SSH_PORT and proto == "TCP":
        # Sort the pair so "A to B" and "B to A" count as one connection.
        pair = tuple(sorted([src_ip, dst_ip]))
        prev_ts = _last_ssh_ts.get(pair)
        is_new_session = prev_ts is None or (ts - prev_ts) >= SSH_SESSION_GAP_SECONDS
        if is_new_session:
            _anomalies.append({
                "type": "SSH_CONNECTION",
                "ts": ts,
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "detail": f"SSH traffic between {src_ip} and {dst_ip}",
            })
        _last_ssh_ts[pair] = ts

    elif (
        learning_period_over
        and port is not None
        and port != DASHBOARD_PORT
        and port not in _known_ports[mac]
    ):
        _anomalies.append({
            "type": "NEW_PORT",
            "ts": ts,
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "detail": f"{src_ip} used port {port}/{proto} for the first time",
        })

    if port is not None:
        _known_ports[mac].add(port)


def detect_anomalies():
    global _last_packet_id, _last_flag_id, _caught_up

    with _lock:
        if not _caught_up:
            # First call after a (re)start: _first_seen/_known_ports are
            # empty again in memory even though the database remembers
            # everything, so replaying the whole history here would both
            # re-flag every device as brand new AND pull millions of old
            # rows into memory in one go - that second part is what used
            # over a gigabyte of RAM and nearly crashed the Pi. Instead,
            # jump straight to "only watch for packets from this moment
            # forward," the same way tailing a log file skips to the end.
            _last_packet_id = database.get_max_packet_id()
            _last_flag_id = database.get_max_flagged_id()
            _caught_up = True
            return list(_anomalies)

        new_packets = database.get_packets_since(_last_packet_id)
        for row in new_packets:
            _process_packet_row(row)
            _last_packet_id = row[0]

        new_flags = database.get_flagged_ips_since(_last_flag_id)
        for row in new_flags:
            flag_id, ts, ip, src_ip, dst_ip = row
            _anomalies.append({
                "type": "MALICIOUS_IP",
                "ts": ts,
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "detail": f"Traffic with known-malicious IP {ip} (between {src_ip} and {dst_ip})",
            })
            _last_flag_id = flag_id

        if new_packets or new_flags:
            # The anomaly list itself stays small (a handful of anomalies,
            # not millions of packets), so re-sorting it here each time
            # something new comes in is cheap even though it's the full list.
            _anomalies.sort(key=lambda a: a["ts"])

        return list(_anomalies)


if __name__ == "__main__":
    anomalies = detect_anomalies()
    if not anomalies:
        print("No anomalies found.")
    else:
        label = "anomaly" if len(anomalies) == 1 else "anomalies"
        print(f"Found {len(anomalies)} {label}:")
        for a in anomalies:
            print(f"  [{a['type']}]  {a['detail']}")
