#!/usr/bin/env python3

# Packet logger: captures live traffic, saves each packet to the database,
# checks it against the threat-intel blocklist, and prints it live.
#
# Needs root to open a live capture:
#     sudo python3 packet_logger.py
# Stop with Ctrl+C.

from scapy.all import sniff, IP, ARP, Ether, TCP, UDP, DNS, DNSQR

import database
import threat_intel

# Ports above this are "ephemeral" - randomly assigned by the OS for one
# connection, not a real service. Linux defaults to 32768-60999.
EPHEMERAL_START = 32768

# The dashboard's own port. Traffic to it is just someone viewing the
# dashboard in a browser, so it's skipped before it reaches the database.
DASHBOARD_PORT = 5000

# How long to wait before flagging the SAME malicious IP again, so one
# ongoing connection doesn't write a new row per packet. Same idea as
# detector.py's SSH session grouping: one alert per "session," not per packet.
MALICIOUS_IP_GAP_SECONDS = 5 * 60

# ip -> timestamp this IP was last flagged.
_last_flagged = {}


def check_threat_intel(ts, src_ip, dst_ip):
    # Check both sides of the packet against the blocklist and record a
    # hit (subject to the cooldown above) for whichever side matches.
    for ip in (src_ip, dst_ip):
        if not threat_intel.is_malicious(ip):
            continue
        prev_ts = _last_flagged.get(ip)
        is_new_hit = prev_ts is None or (ts - prev_ts) >= MALICIOUS_IP_GAP_SECONDS
        if is_new_hit:
            database.save_flagged_ip(ts, ip, src_ip, dst_ip)
            print(f"{ts:.3f}  !! THREAT INTEL MATCH: {ip} (seen between {src_ip} and {dst_ip})")
        _last_flagged[ip] = ts


def service_port(sport, dport):
    # Given a connection's two ports, figure out which one (if either)
    # is the actual service, rather than a random port the OS picked.
    s_eph = sport >= EPHEMERAL_START
    d_eph = dport >= EPHEMERAL_START
    if s_eph and not d_eph:
        return dport
    if d_eph and not s_eph:
        return sport
    if not s_eph and not d_eph:
        return min(sport, dport)
    return None


def handle_packet(pkt):
    ts = pkt.time
    size = len(pkt)

    if pkt.haslayer(ARP):
        arp = pkt[ARP]
        mac = arp.hwsrc
        src_ip = arp.psrc
        dst_ip = arp.pdst
        database.save_packet(ts, mac, src_ip, dst_ip, proto="ARP", port=None, size=size)
        print(f"{ts:.3f}  ARP  {mac}  {src_ip} -> {dst_ip}  {size} bytes")
        return

    if not pkt.haslayer(IP):
        return

    if pkt.haslayer(Ether):
        mac = pkt[Ether].src
    else:
        # No Ethernet layer means VPN/tunnel traffic (e.g. Tailscale),
        # which has no MAC address since it's not a real network card.
        mac = "N/A"

    src_ip = pkt[IP].src
    dst_ip = pkt[IP].dst

    check_threat_intel(ts, src_ip, dst_ip)

    proto = None
    port = None
    if pkt.haslayer(TCP):
        sport, dport = int(pkt[TCP].sport), int(pkt[TCP].dport)
        proto = "TCP"
        port = service_port(sport, dport)
    elif pkt.haslayer(UDP):
        sport, dport = int(pkt[UDP].sport), int(pkt[UDP].dport)
        proto = "UDP"
        port = service_port(sport, dport)

    if port == DASHBOARD_PORT:
        return

    dns_query = None
    if pkt.haslayer(DNS) and pkt[DNS].qr == 0 and pkt.haslayer(DNSQR):
        dns_query = pkt[DNSQR].qname.decode(errors="ignore").rstrip(".")

    database.save_packet(ts, mac, src_ip, dst_ip, proto, port, size, dns_query)

    port_info = f"  port={port}/{proto}" if port else ""
    dns_info = f"  dns={dns_query}" if dns_query else ""
    print(f"{ts:.3f}  IP   {mac}  {src_ip} -> {dst_ip}  {size} bytes{port_info}{dns_info}")


def start_sniffing():
    # Runs forever, so it lives in a function rather than directly under
    # __main__ - that's what lets main.py run this in a background thread
    # while the dashboard runs in the main thread.
    database.init_db()
    # Load the blocklist here too, so running this file standalone still
    # has it available (main.py's threat_intel_loop keeps it refreshed
    # when running through there instead).
    threat_intel.update_blocklist()
    # eth0 is the direct Ethernet link to your PC - what actually lets the
    # detector see your PC's real traffic before NAT rewrites it. wlan1 is
    # the Pi's own WiFi uplink, so other devices on your home network still
    # get seen too. The filter drops anything that isn't IP or ARP at the
    # kernel level, before it ever reaches handle_packet() - this matches
    # exactly what handle_packet() already keeps, so it's free performance:
    # fewer packets built into Python objects for no behavior change.
    sniff(prn=handle_packet, store=False, iface=["eth0", "wlan1"], filter="ip or arp")


if __name__ == "__main__":
    start_sniffing()
