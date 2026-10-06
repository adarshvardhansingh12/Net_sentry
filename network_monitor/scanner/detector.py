"""
detector.py
The "brain" of the project. Takes a freshly scanned device list and decides
whether anything is suspicious, using simple rule-based logic first.

Rules implemented (each is a separate function so your team can add more):
1. NEW_DEVICE      -> a MAC address never seen before joins the network
2. NOT_BASELINE     -> a known-but-not-trusted device is active outside expected hours
3. TRAFFIC_OUTLIER  -> a device is transferring far more data than its own history

This file intentionally keeps thresholds as named constants at the top —
tune these during Phase 3 testing instead of hunting through the logic.
"""

from datetime import datetime
import db

# ---- Tunable thresholds (adjust these during testing) ----
TRAFFIC_OUTLIER_MULTIPLIER = 3.0   # flag if traffic is 3x a device's own average
QUIET_HOURS_START = 1              # 1 AM
QUIET_HOURS_END = 5                # 5 AM


def check_new_device(mac, ip, is_first_seen):
    """Rule 1: flag any device we have never seen before."""
    if is_first_seen:
        message = f"New device joined the network: {mac} ({ip})"
        db.create_alert(mac, ip, "NEW_DEVICE", message)
        return message
    return None


def check_quiet_hours_activity(mac, ip):
    """Rule 2: flag a non-baseline device that's active during unusual hours."""
    now = datetime.now()
    if QUIET_HOURS_START <= now.hour < QUIET_HOURS_END:
        if not db.is_baseline_device(mac):
            message = (
                f"Non-trusted device active during quiet hours "
                f"({now.strftime('%H:%M')}): {mac} ({ip})"
            )
            db.create_alert(mac, ip, "QUIET_HOURS", message)
            return message
    return None


def check_traffic_outlier(mac, ip, current_bytes):
    """Rule 3: flag if current traffic is far above this device's own average."""
    average = db.get_average_bytes_for_device(mac)
    if average > 0 and current_bytes > average * TRAFFIC_OUTLIER_MULTIPLIER:
        message = (
            f"Unusual traffic spike from {mac} ({ip}): "
            f"{current_bytes} bytes vs. average {average:.0f}"
        )
        db.create_alert(mac, ip, "TRAFFIC_OUTLIER", message)
        return message
    return None


def run_all_checks(mac, ip, is_first_seen, current_bytes=0):
    """
    Runs every detection rule for a single device and returns a list of
    triggered alert messages (empty list = nothing suspicious).
    """
    triggered = []

    result = check_new_device(mac, ip, is_first_seen)
    if result:
        triggered.append(result)

    result = check_quiet_hours_activity(mac, ip)
    if result:
        triggered.append(result)

    result = check_traffic_outlier(mac, ip, current_bytes)
    if result:
        triggered.append(result)

    return triggered
