"""
main.py
The monitoring loop. Run this to start watching your network:

    python main.py

Every SCAN_INTERVAL_SECONDS, it will:
  1. Scan the network for active devices
  2. Record/update them in the database
  3. Run detection rules on each device
  4. Dispatch alerts for anything suspicious

Leave this running in a terminal (or as a background service on a
Raspberry Pi) for continuous monitoring.
"""

import time

import db
import scanner
import detector
import alerts

SCAN_INTERVAL_SECONDS = 30

# Set this to True to actively scan the whole subnet (finds silent/idle
# devices too, not just ones your laptop already talked to). Requires:
#   - scapy installed (already in requirements.txt)
#   - Npcap installed on Windows (https://npcap.com)
#   - Running PowerShell as Administrator
# If any of those aren't set up, this safely falls back to the passive
# ARP table method instead of crashing.
USE_ACTIVE_SCAN = True

# Set this to True to query an online API (api.macvendors.com) whenever a
# device's vendor isn't found in our offline table. Needs internet access
# and only runs once per new device (cached afterward), so it won't slow
# down repeat scans or hit rate limits. Set to False to stay fully offline.
USE_ONLINE_VENDOR_LOOKUP = True


def run_one_scan_cycle():
    devices = scanner.get_devices_from_arp_table()

    if USE_ACTIVE_SCAN:
        active_devices = scanner.get_devices_active_scan()
        # Merge with the passive results, de-duplicating by MAC address
        seen_macs = {d["mac"] for d in devices}
        for d in active_devices:
            if d["mac"] not in seen_macs:
                devices.append(d)
                seen_macs.add(d["mac"])

    print(f"\n[main] Scan found {len(devices)} device(s) at this moment.")

    # Only bother with mDNS discovery (which takes a few seconds) if there's
    # at least one device we haven't named yet — keeps steady-state scans fast.
    unnamed_devices_present = any(d["mac"] not in _known_macs_cache for d in devices)
    mdns_map = scanner.discover_mdns_hostnames(timeout=3) if unnamed_devices_present else {}

    for device in devices:
        mac = device["mac"]
        ip = device["ip"]
        already_known = mac in _known_macs_cache

        # Vendor lookup: only hit the (rate-limited, internet-dependent)
        # online fallback API for devices we've never resolved before.
        # Already-known devices reuse whatever vendor is already stored.
        if already_known:
            vendor = "unknown"  # placeholder — upsert_device won't overwrite existing vendor anyway
        else:
            vendor = scanner.lookup_vendor(mac, allow_online_fallback=USE_ONLINE_VENDOR_LOOKUP)

        # Hostname lookups are slow (DNS/NetBIOS/mDNS timeouts), so only
        # bother resolving a name the first time we see a device — after
        # that we already have it stored and don't need to look it up again.
        hostname = "unknown" if already_known else scanner.get_hostname(ip, mdns_map=mdns_map)
        _known_macs_cache.add(mac)

        is_first_seen = db.upsert_device(mac, ip, hostname=hostname, vendor=vendor)
        db.log_connection(mac, ip, bytes_transferred=0)  # hook up real traffic stats later

        triggered = detector.run_all_checks(mac, ip, is_first_seen)
        for message in triggered:
            alerts.dispatch(message)


_known_macs_cache = set()


def main():
    print("[main] Initializing database...")
    db.init_db()

    print(f"[main] Starting monitoring loop (every {SCAN_INTERVAL_SECONDS}s). Ctrl+C to stop.")
    try:
        while True:
            run_one_scan_cycle()
            time.sleep(SCAN_INTERVAL_SECONDS)
    except KeyboardInterrupt:
        print("\n[main] Stopped by user.")


if __name__ == "__main__":
    main()