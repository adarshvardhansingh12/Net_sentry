"""
traffic_monitor.py
Lightweight, Wireshark-style packet capture for METADATA only — source/
destination IP, port, protocol, and packet size. This deliberately never
reads, stores, or displays payload content (the actual data inside a
connection — a webpage, a message, a video stream). Most traffic is
encrypted (HTTPS) anyway, so payload inspection wouldn't work without
intercepting encryption — which is a much more invasive technique than
this project is designed for.

This gives an organization real traffic-volume and protocol visibility
(useful for spotting bandwidth abuse, unusual protocols, or a device
suddenly talking to an unexpected number of destinations) without ever
seeing what any individual is actually doing or viewing.

Deployment note: network monitoring on infrastructure YOU own/administer
is standard security practice (this is what enterprise IDS/IPS and
NetFlow-style tools do) — but should be run under a documented security
policy, with monitoring disclosed to users via an IT Acceptable Use
Policy, consistent with your organization's obligations under applicable
law. This tool intentionally never touches payload content, which
reduces (but doesn't eliminate) the privacy considerations involved in
deploying it — that responsibility sits with whoever deploys and
operates it, not with the code itself.
"""

import threading
import time
from collections import deque, defaultdict

# Common ports mapped to a human-readable protocol/service label.
# This is service-level classification (e.g. "this is HTTPS traffic"),
# NOT content inspection (we never look at what's inside the HTTPS
# connection — that's encrypted and none of this tool's business).
PORT_LABELS = {
    80: "HTTP", 443: "HTTPS", 53: "DNS", 22: "SSH", 21: "FTP",
    25: "SMTP", 110: "POP3", 143: "IMAP", 3389: "RDP", 445: "SMB",
    3306: "MySQL", 5432: "PostgreSQL", 67: "DHCP", 68: "DHCP",
    123: "NTP", 993: "IMAPS", 995: "POP3S", 587: "SMTP (submission)",
}

_lock = threading.Lock()
_mac_bytes = defaultdict(int)          # mac -> bytes seen since last reset
_protocol_totals = defaultdict(int)    # protocol label -> cumulative bytes
_recent_packets = deque(maxlen=100)    # rolling log of recent packet HEADERS only
_sniffer = None


def _label_for_port(port):
    return PORT_LABELS.get(port, f"port {port}")


def _handle_packet(pkt):
    """
    Called once per captured packet by scapy. Reads ONLY header fields
    (source/destination address, port, protocol, total length) — the
    payload/data portion of the packet is never accessed or stored.
    """
    try:
        from scapy.all import IP, TCP, UDP, Ether

        if IP not in pkt or Ether not in pkt:
            return

        length = len(pkt)
        src_ip = pkt[IP].src
        dst_ip = pkt[IP].dst

        if TCP in pkt:
            proto = "TCP"
            port = pkt[TCP].dport if pkt[TCP].dport in PORT_LABELS else pkt[TCP].sport
        elif UDP in pkt:
            proto = "UDP"
            port = pkt[UDP].dport if pkt[UDP].dport in PORT_LABELS else pkt[UDP].sport
        else:
            proto = "OTHER"
            port = 0

        label = _label_for_port(port) if port else proto

        with _lock:
            # Attribute traffic volume to whichever side is the local
            # device sending this packet — good enough for volume/anomaly
            # purposes without needing full flow reconstruction.
            _mac_bytes[pkt[Ether].src.lower()] += length
            _protocol_totals[label] += length
            _recent_packets.append({
                "time": time.strftime("%H:%M:%S"),
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "protocol": label,
                "size": length,
            })
    except Exception:
        pass  # a single malformed/unusual packet should never crash capture


def start_capture():
    """
    Starts a background packet sniffer (metadata only, see module
    docstring). Safe to call once at program startup. Requires scapy +
    admin/root privileges + Npcap on Windows — same requirements as
    active scan mode. Fails gracefully (prints a message, doesn't crash
    the rest of the tool) if any of those aren't available.
    """
    global _sniffer
    try:
        from scapy.all import AsyncSniffer
    except ImportError:
        print("[traffic_monitor] scapy not installed — traffic capture disabled.")
        return

    try:
        _sniffer = AsyncSniffer(prn=_handle_packet, store=False)
        _sniffer.start()
        print("[traffic_monitor] Packet capture started (headers/metadata only — no payload inspection).")
    except PermissionError:
        print("[traffic_monitor] Traffic capture needs administrator privileges.")
    except OSError as e:
        print(f"[traffic_monitor] Traffic capture failed — is Npcap installed? Error: {e}")


def stop_capture():
    global _sniffer
    if _sniffer:
        _sniffer.stop()
        _sniffer = None


def get_and_reset_mac_bytes():
    """
    Returns {mac: bytes_seen_since_last_call} and resets the counters.
    Call this once per scan cycle so each cycle reports fresh volume for
    that interval, not a running total since the program started — this
    is what feeds the TRAFFIC_OUTLIER detection rule in detector.py.
    """
    with _lock:
        result = dict(_mac_bytes)
        _mac_bytes.clear()
        return result


def get_protocol_totals():
    """Cumulative bytes per protocol/service since the program started."""
    with _lock:
        return dict(_protocol_totals)


def get_recent_packets(limit=50):
    """Most recent captured packet HEADERS (no payload) for the dashboard."""
    with _lock:
        return list(_recent_packets)[-limit:]