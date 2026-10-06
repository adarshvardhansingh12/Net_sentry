# Rogue Device & Network Anomaly Detector

A network monitoring tool that watches your local network, learns which
devices are "normal," and alerts you when something unexpected shows up —
a new device, unusual traffic, or activity at odd hours.

## How it works

```
scanner.py  -->  db.py (SQLite)  -->  detector.py  -->  alerts.py
   |                  ^
   +------------------+
   (dashboard/app.py reads from the same database to show a live web UI)
```

1. `scanner.py` finds devices currently on your network (via the ARP table)
2. `db.py` stores them and their connection history
3. `detector.py` checks each device against simple rules (new device, odd
   hours, traffic spike)
4. `alerts.py` sends a notification (email/Discord) when a rule triggers
5. `dashboard/app.py` shows everything in a live web page

## Setup

```bash
pip install -r requirements.txt
```

## Running it

**Terminal 1 — start the monitor:**
```bash
cd scanner
python main.py
```

**Terminal 2 — start the dashboard:**
```bash
cd dashboard
python app.py
```

Then open **http://localhost:5000** in your browser. It refreshes every
10 seconds automatically.

## Team task split (suggested for 4 people)

| Person | Owns | Files |
|---|---|---|
| 1 | Network scanning — get active scan mode working with scapy, handle MAC randomization | `scanner/scanner.py` |
| 2 | Detection logic — add more rules, tune thresholds during testing | `scanner/detector.py` |
| 3 | Dashboard — improve the UI, add charts, filtering, device details | `dashboard/` |
| 4 | Alerts + testing — set up email/Discord, run "attack" simulations, write the report | `scanner/alerts.py` |

## What to build next (in roadmap order)

**Phase 2 remaining work:**
- Switch from `get_devices_from_arp_table()` to `get_devices_active_scan()`
  in `scanner.py` (needs `sudo python main.py` since scapy needs raw socket
  access) — this catches devices the passive ARP table misses
- Replace the tiny built-in vendor list in `lookup_vendor()` with the full
  IEEE OUI database (free download, thousands of entries) for accurate
  vendor identification

**Phase 3 work:**
- Wire up real traffic byte counts in `main.py` (currently hardcoded to 0) —
  use scapy to sum packet sizes per MAC during each scan interval
- After a ~1 week "training period" of normal use, call
  `db.mark_as_baseline(mac)` for every device that should be trusted
- Tune `TRAFFIC_OUTLIER_MULTIPLIER` and quiet hours in `detector.py` based
  on false-positive rate during testing

**Phase 4 work:**
- Add device fingerprinting (guess OS from TTL) for more useful alerts
- Polish the dashboard (search/filter, alert acknowledgment button)
- Rehearse the live demo: have a teammate join the network with an
  unrecognized device during the presentation and show the real-time alert

## Important note on permissions

Only run this against a network you own or have **explicit written
permission** to monitor (your own home network, or a lab network with
instructor/IT sign-off). Passive ARP table reading is generally fine on
your own network; active scanning and packet sniffing on a network you
don't control or lack permission for can violate policy or law.
