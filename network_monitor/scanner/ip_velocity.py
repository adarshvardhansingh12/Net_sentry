"""
ip_velocity.py -- IP Velocity & Geo-Distance Tracking

Objective
---------
Detect proxy rotation, VPN switching and distributed botnets by flagging
rapid source-IP changes for the same identity (user / session / API key)
that break physical travel constraints.

Two independent signals
-----------------------
1. Impossible travel: the implied speed between two consecutive IP sightings
   (great-circle distance / elapsed time) is faster than a commercial jet.
2. IP rotation: too many distinct IPs for one identity inside a short window,
   which is what proxy pools and botnets look like even when the geo points
   are close together (so the travel check alone would miss them).

Notes
-----
* Geolocation is pluggable. Pass any callable `ip -> (lat, lon) | None`.
  `make_geoip2_lookup()` wraps the free MaxMind GeoLite2-City database
  (needs `pip install geoip2` plus a free GeoLite2 account for the .mmdb).
* Private / loopback / link-local addresses have no geolocation, so they are
  skipped. This detector is meant for identities seen from public IPs
  (e.g. logins to a service you expose), not for pure LAN traffic.
* False-positive sources: mobile carrier NAT, corporate VPNs, iCloud Private
  Relay. That is why the thresholds are tunable and alerts have a cooldown.
"""
from __future__ import annotations

import ipaddress
import math
import threading
import time
from collections import deque
from dataclasses import dataclass, field
from typing import Callable, Deque, Dict, List, Optional, Tuple

EARTH_RADIUS_KM = 6371.0088

GeoPoint = Tuple[float, float]                  # (latitude, longitude)
GeoLookup = Callable[[str], Optional[GeoPoint]]


@dataclass
class Alert:
    """Common alert shape (move to a shared module if you prefer)."""
    detector: str
    identity: str
    severity: str            # "low" | "medium" | "high" | "critical"
    kind: str                # short machine-readable code
    message: str             # human-readable explanation
    timestamp: float
    details: dict = field(default_factory=dict)


def haversine_km(a: GeoPoint, b: GeoPoint) -> float:
    """Great-circle distance between two (lat, lon) points in kilometres."""
    lat1, lon1 = map(math.radians, a)
    lat2, lon2 = map(math.radians, b)
    dlat, dlon = lat2 - lat1, lon2 - lon1
    h = (math.sin(dlat / 2) ** 2
         + math.cos(lat1) * math.cos(lat2) * math.sin(dlon / 2) ** 2)
    return 2 * EARTH_RADIUS_KM * math.asin(min(1.0, math.sqrt(h)))


def make_geoip2_lookup(mmdb_path: str) -> GeoLookup:
    """Build a GeoLookup backed by a local GeoLite2-City .mmdb file (free)."""
    import geoip2.database  # optional dependency, imported lazily

    reader = geoip2.database.Reader(mmdb_path)

    def lookup(ip: str) -> Optional[GeoPoint]:
        try:
            loc = reader.city(ip).location
        except Exception:        # AddressNotFoundError, bad input, etc.
            return None
        if loc.latitude is None or loc.longitude is None:
            return None
        return (loc.latitude, loc.longitude)

    return lookup


def _is_public_ip(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_global
    except ValueError:
        return False


@dataclass
class _Sighting:
    ts: float
    ip: str
    point: Optional[GeoPoint]


class IPVelocityDetector:
    name = "ip_velocity"

    def __init__(
        self,
        geo_lookup: GeoLookup,
        *,
        max_speed_kmh: float = 900.0,      # roughly airliner cruise speed
        min_distance_km: float = 100.0,    # ignore jitter between nearby cities
        rotation_window_s: float = 300.0,
        rotation_max_ips: int = 4,         # >4 distinct IPs in 5 min = suspicious
        alert_cooldown_s: float = 60.0,
        history_per_identity: int = 100,
    ) -> None:
        self._geo_lookup = geo_lookup
        self.max_speed_kmh = max_speed_kmh
        self.min_distance_km = min_distance_km
        self.rotation_window_s = rotation_window_s
        self.rotation_max_ips = rotation_max_ips
        self.alert_cooldown_s = alert_cooldown_s
        self.history_per_identity = history_per_identity

        self._history: Dict[str, Deque[_Sighting]] = {}
        self._last_alert: Dict[Tuple[str, str], float] = {}
        self._lock = threading.Lock()

    # ------------------------------------------------------------------ API
    def observe(self, identity: str, ip: str, ts: Optional[float] = None) -> List[Alert]:
        """Record that `identity` was seen from `ip`; return any alerts raised."""
        ts = time.time() if ts is None else ts
        if not _is_public_ip(ip):
            return []

        point = self._geo_lookup(ip)      # outside the lock: may touch disk

        with self._lock:
            hist = self._history.setdefault(
                identity, deque(maxlen=self.history_per_identity))

            # Same IP as last time: just refresh the timestamp, nothing changed.
            if hist and hist[-1].ip == ip:
                hist[-1].ts = max(hist[-1].ts, ts)
                return []

            new = _Sighting(ts, ip, point)
            prev = hist[-1] if hist else None
            alerts: List[Alert] = []

            # Out-of-order events would give negative elapsed time; skip travel
            # maths for them rather than guess.
            if prev is not None and ts >= prev.ts:
                alerts += self._check_travel(identity, prev, new)

            hist.append(new)
            alerts += self._check_rotation(identity, hist, ts)
            return self._apply_cooldown(alerts)

    def purge(self, max_age_s: float = 86400.0, now: Optional[float] = None) -> int:
        """Drop identities not seen for `max_age_s`. Returns how many were removed."""
        now = time.time() if now is None else now
        with self._lock:
            stale = [k for k, h in self._history.items() if not h or now - h[-1].ts > max_age_s]
            for k in stale:
                del self._history[k]
            self._last_alert = {k: t for k, t in self._last_alert.items()
                                if now - t < max_age_s}
            return len(stale)

    # ------------------------------------------------------------- internals
    def _check_travel(self, identity: str, prev: _Sighting, new: _Sighting) -> List[Alert]:
        if prev.point is None or new.point is None:
            return []
        dist = haversine_km(prev.point, new.point)
        if dist < self.min_distance_km:
            return []
        # Floor elapsed time at 1 s so identical timestamps don't divide by zero.
        hours = max(new.ts - prev.ts, 1.0) / 3600.0
        speed = dist / hours
        if speed <= self.max_speed_kmh:
            return []
        severity = "critical" if speed > 3 * self.max_speed_kmh else "high"
        return [Alert(
            self.name, identity, severity, "impossible_travel",
            f"{prev.ip} -> {new.ip}: {dist:.0f} km in {hours * 60:.1f} min "
            f"(~{speed:.0f} km/h exceeds {self.max_speed_kmh:.0f} km/h)",
            new.ts,
            {"from_ip": prev.ip, "to_ip": new.ip, "distance_km": round(dist, 1),
             "speed_kmh": round(speed, 1), "elapsed_s": round(new.ts - prev.ts, 1)},
        )]

    def _check_rotation(self, identity: str, hist: Deque[_Sighting], now: float) -> List[Alert]:
        cutoff = now - self.rotation_window_s
        ips = {s.ip for s in hist if s.ts >= cutoff}
        if len(ips) <= self.rotation_max_ips:
            return []
        return [Alert(
            self.name, identity, "medium", "ip_rotation",
            f"{len(ips)} distinct IPs within {self.rotation_window_s:.0f}s "
            f"(limit {self.rotation_max_ips}) -- possible proxy pool / botnet",
            now, {"distinct_ips": sorted(ips), "window_s": self.rotation_window_s},
        )]

    def _apply_cooldown(self, alerts: List[Alert]) -> List[Alert]:
        """Suppress repeats of the same (identity, kind) alert inside the cooldown."""
        out = []
        for a in alerts:
            key = (a.identity, a.kind)
            last = self._last_alert.get(key)
            if last is None or a.timestamp - last >= self.alert_cooldown_s:
                self._last_alert[key] = a.timestamp
                out.append(a)
        return out


# ------------------------------------------------------------------- demo
if __name__ == "__main__":
    # Stub geo table so the demo runs offline. Real use: make_geoip2_lookup(...)
    fake_geo = {
        "8.8.8.8": (37.39, -122.08),     # California
        "1.1.1.1": (-33.87, 151.21),     # Sydney
        "4.4.4.4": (40.71, -74.00),
        "5.5.5.5": (40.73, -74.02),
        "6.6.6.6": (40.69, -73.99),
        "7.7.7.7": (40.75, -73.98),
        "9.9.9.9": (40.70, -74.01),
    }
    det = IPVelocityDetector(lambda ip: fake_geo.get(ip))

    t0 = 1_700_000_000.0
    print("-- impossible travel (California -> Sydney in 2 minutes)")
    det.observe("alice", "8.8.8.8", t0)
    for a in det.observe("alice", "1.1.1.1", t0 + 120):
        print(f"[{a.severity}] {a.kind}: {a.message}")

    print("-- proxy rotation (5 IPs in ~1 minute, all in NYC)")
    for i, ip in enumerate(["4.4.4.4", "5.5.5.5", "6.6.6.6", "7.7.7.7", "9.9.9.9"]):
        for a in det.observe("bob", ip, t0 + i * 12):
            print(f"[{a.severity}] {a.kind}: {a.message}")
