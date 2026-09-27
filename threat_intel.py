#!/usr/bin/env python3

# Threat intel: downloads FireHOL's Level 2 blocklist (known-malicious IP
# ranges - broader coverage than Level 1, at the cost of a somewhat higher
# false-positive rate) and provides a fast is_malicious() check for
# packet_logger.py to call on every captured packet.

import bisect
import ipaddress
import os

import requests

FIREHOL_BLOCKLIST_URL = "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level2.netset"
CACHE_FILE = "malicious_ips.netset"

# How often main.py should re-download the list. Once a day is plenty.
REFRESH_INTERVAL_SECONDS = 24 * 60 * 60

# RFC 6598 "Shared Address Space" (100.64.0.0/10) - what Tailscale uses for
# its virtual 100.x.x.x addresses. Python's ipaddress module doesn't treat
# this as private/reserved on its own, so it's checked separately below.
_SHARED_ADDRESS_SPACE = ipaddress.ip_network("100.64.0.0/10")

# The active lookup table: every blocked network's start/end address, kept
# sorted so is_malicious() can binary-search instead of scanning thousands
# of ranges one by one. Rebuilt every time the list refreshes.
_starts = []
_ends = []


def download_blocklist():
    # Fetch the latest list and cache it locally, so there's still
    # something to check against if a future download fails.
    response = requests.get(FIREHOL_BLOCKLIST_URL, timeout=30)
    response.raise_for_status()
    with open(CACHE_FILE, "w") as f:
        f.write(response.text)


def _parse_cache_file():
    # Turn the cached file's lines into ip_network objects, skipping
    # comments/blanks and any line that isn't a valid IP/CIDR.
    networks = []
    if not os.path.exists(CACHE_FILE):
        return networks
    with open(CACHE_FILE) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            try:
                networks.append(ipaddress.ip_network(line, strict=False))
            except ValueError:
                continue
    return networks


def reload_lookup_table():
    # Rebuild the sorted start/end arrays used by is_malicious()'s binary
    # search. Called once at startup and again after every refresh.
    global _starts, _ends
    networks = sorted(_parse_cache_file(), key=lambda n: int(n.network_address))
    _starts = [int(n.network_address) for n in networks]
    _ends = [int(n.broadcast_address) for n in networks]


def is_checkable_public_ip(ip_str):
    # True only for a genuine public IP. FireHOL's list includes "bogon"
    # ranges (private/reserved addresses, like your own LAN or Tailscale's
    # range) meant to catch spoofed traffic on real internet routers - on
    # a home network those addresses show up constantly and legitimately,
    # so this filter runs before is_malicious() ever checks the list, to
    # keep normal LAN traffic from being flagged as malicious.
    try:
        ip_obj = ipaddress.ip_address(ip_str)
    except ValueError:
        return False
    return not (
        ip_obj.is_private
        or ip_obj.is_reserved
        or ip_obj.is_loopback
        or ip_obj.is_link_local
        or ip_obj.is_multicast
        or ip_obj in _SHARED_ADDRESS_SPACE
    )


def is_malicious(ip_str):
    # Binary search: find where this IP would sit among the sorted start
    # addresses - the only range that could possibly contain it is the one
    # immediately before that point, so there's no need to check the rest.
    if not is_checkable_public_ip(ip_str):
        return False
    if not _starts:
        return False

    ip_int = int(ipaddress.ip_address(ip_str))
    idx = bisect.bisect_right(_starts, ip_int) - 1
    if idx < 0:
        return False
    return _starts[idx] <= ip_int <= _ends[idx]


def update_blocklist():
    # Download the latest list and reload the lookup table from it. A
    # failed download just falls back to whatever was cached last time.
    try:
        download_blocklist()
    except Exception as e:
        print(f"Failed to download threat intel blocklist: {e}")
    reload_lookup_table()
    print(f"Threat intel blocklist loaded: {len(_starts)} network ranges")


if __name__ == "__main__":
    update_blocklist()
    print("Testing a known-safe public IP (Cloudflare DNS):", is_malicious("1.1.1.1"))
    print("Testing a private LAN IP (should always be False):", is_malicious("192.168.1.10"))
