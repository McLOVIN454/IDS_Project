#!/usr/bin/env python3

# Dashboard: a small Flask app that shows captured traffic and detected
# anomalies in a browser, instead of digging through SQL or script output.
#
# Run with:
#     python3 dashboard.py
# Then open http://localhost:5000. No sudo needed - this only reads the
# database and serves a webpage, it never touches the network capture.

from datetime import datetime

from flask import Flask, render_template

import database
import detector

app = Flask(__name__)


def format_packet(row):
    # Turn a raw database row (tuple) into a dict with a human-readable
    # time, so the template can refer to fields by name.
    row_id, ts, mac, src_ip, dst_ip, proto, port, size, dns_query = row
    return {
        "id": row_id,
        "time": datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S"),
        "mac": mac,
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "proto": proto,
        "port": port,
        "size": size,
        "dns_query": dns_query,
    }


def format_anomaly(anomaly):
    # Same idea, for one anomaly dict from detector.py.
    return {
        "type": anomaly["type"],
        "time": datetime.fromtimestamp(anomaly["ts"]).strftime("%Y-%m-%d %H:%M:%S"),
        "detail": anomaly["detail"],
    }


@app.route("/")
def home():
    recent_rows = database.get_recent_packets(limit=20)
    packets = [format_packet(row) for row in recent_rows]

    all_anomalies = detector.detect_anomalies()
    # Newest first, capped at 20 so the page doesn't get huge.
    recent_anomalies = [format_anomaly(a) for a in reversed(all_anomalies)][:20]

    return render_template("dashboard.html", packets=packets, anomalies=recent_anomalies)


if __name__ == "__main__":
    app.run(debug=True, port=5000)
