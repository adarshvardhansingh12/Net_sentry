"""
payload_uniformity.py -- Payload Size Uniformity Detection

Objective
---------
Expose automated credential-stuffing and scripting tools by analysing the
variance of application-layer Content-Length values and flagging unnaturally
uniform (zero or near-zero variance) request sizes across many sources.

Why this works
--------------
A real login form body is "username=<x>&password=<y>": every human types a
different-length username and password, so sizes vary a lot. A script that
replays a fixed template, or a botnet hitting one endpoint with fixed-size
bodies, produces identical or almost identical sizes from many different
sources at once. One client sending same-size requests can be legitimate
(a poller); MANY distinct sources doing it to the same endpoint is not.

Three triggers (any one fires, evaluated per endpoint in a sliding window)
  * zero variance           -- every length identical
  * low coefficient of variation (stdev / mean <= cv_threshold)
  * dominant length         -- one exact length makes up >= mode_ratio_threshold

Limits
------
Content-Length is an HTTP header. You can read it on plaintext HTTP, at a
reverse proxy / WAF, or in application logs -- not from encrypted HTTPS on
the wire. Feed this detector from wherever you can see headers. It never
needs (or looks at) the payload content itself, which fits NetGuardian's
metadata-only privacy rule. Only point it at endpoints where bodies are
expected to vary (login, signup, search); fixed-size heartbeats will
trigger it by design.
"""
from __future__ import annotations

import statistics
import threading
import time
from collections import Counter, deque
from dataclasses import dataclass, field
from typing import Deque, Dict, List, Optional


@dataclass
class Alert:
    """Common alert shape (move to a shared module if you prefer)."""
    detector: str
    identity: str            # here: the endpoint being attacked
    severity: str
    kind: str
    message: str
    timestamp: float
    details: dict = field(default_factory=dict)


@dataclass
class _Req:
    ts: float
    source: str
    length: int


class PayloadUniformityDetector:
    name = "payload_uniformity"

    def __init__(
        self,
        *,
        window_s: float = 600.0,
        min_samples: int = 20,             # need enough data for variance to mean anything
        min_distinct_sources: int = 5,     # "distributed" requirement
        cv_threshold: float = 0.01,        # stdev below 1% of the mean = near-constant
        mode_ratio_threshold: float = 0.9,
        ignore_zero_length: bool = True,   # GETs / empty bodies carry no signal
        max_samples_per_endpoint: int = 1000,
        alert_cooldown_s: float = 120.0,
    ) -> None:
        self.window_s = window_s
        self.min_samples = min_samples
        self.min_distinct_sources = min_distinct_sources
        self.cv_threshold = cv_threshold
        self.mode_ratio_threshold = mode_ratio_threshold
        self.ignore_zero_length = ignore_zero_length
        self.max_samples = max_samples_per_endpoint
        self.alert_cooldown_s = alert_cooldown_s

        self._reqs: Dict[str, Deque[_Req]] = {}
        self._last_alert: Dict[str, float] = {}
        self._lock = threading.Lock()

    # ------------------------------------------------------------------ API
    def observe(self, endpoint: str, source: str, content_length: int,
                ts: Optional[float] = None) -> List[Alert]:
        """Record one request (endpoint, source IP/ID, Content-Length)."""
        ts = time.time() if ts is None else ts
        try:
            length = int(content_length)
        except (TypeError, ValueError):
            return []
        if length < 0 or (self.ignore_zero_length and length == 0):
            return []

        with self._lock:
            q = self._reqs.setdefault(endpoint, deque(maxlen=self.max_samples))
            q.append(_Req(ts, source, length))
            cutoff = ts - self.window_s
            while q and q[0].ts < cutoff:
                q.popleft()

            if len(q) < self.min_samples:
                return []
            sources = {r.source for r in q}
            if len(sources) < self.min_distinct_sources:
                return []

            lengths = [r.length for r in q]
            mean = statistics.fmean(lengths)
            stdev = statistics.pstdev(lengths)
            cv = stdev / mean if mean > 0 else 0.0
            mode_len, mode_count = Counter(lengths).most_common(1)[0]
            mode_ratio = mode_count / len(lengths)

            triggers = []
            if stdev == 0:
                triggers.append("zero_variance")
            elif cv <= self.cv_threshold:
                triggers.append("low_variation")
            if mode_ratio >= self.mode_ratio_threshold:
                triggers.append("dominant_length")
            if not triggers:
                return []

            last = self._last_alert.get(endpoint)
            if last is not None and ts - last < self.alert_cooldown_s:
                return []
            self._last_alert[endpoint] = ts

            severity = "high" if "zero_variance" in triggers else "medium"
            return [Alert(
                self.name, endpoint, severity, "uniform_payload_sizes",
                f"{len(q)} requests from {len(sources)} sources to {endpoint} have "
                f"near-identical sizes (mean {mean:.0f} B, stdev {stdev:.2f}, "
                f"{mode_ratio:.0%} are exactly {mode_len} B) -- scripted/automated",
                ts,
                {"triggers": triggers, "samples": len(q), "distinct_sources": len(sources),
                 "mean": round(mean, 2), "stdev": round(stdev, 3), "cv": round(cv, 5),
                 "mode_length": mode_len, "mode_ratio": round(mode_ratio, 3)},
            )]

    def purge(self, now: Optional[float] = None) -> int:
        """Drop endpoints with no requests left in the window."""
        now = time.time() if now is None else now
        with self._lock:
            stale = [e for e, q in self._reqs.items()
                     if not q or q[-1].ts < now - self.window_s]
            for e in stale:
                del self._reqs[e]
                self._last_alert.pop(e, None)
            return len(stale)


# ------------------------------------------------------------------- demo
if __name__ == "__main__":
    import random

    random.seed(7)
    det = PayloadUniformityDetector()
    t = 1_700_000_000.0

    print("-- humans: varied body sizes from many sources")
    fired = False
    for i in range(40):
        for a in det.observe("/login", f"10.0.0.{i % 12}", random.randint(28, 95), t + i):
            fired, _ = True, print(f"[{a.severity}] {a.message}")
    print("alerts:", "yes" if fired else "none (expected)")

    print("-- botnet: identical 47-byte bodies from many sources")
    for i in range(40):
        for a in det.observe("/api/auth", f"203.0.{i % 10}.9", 47, t + i):
            print(f"[{a.severity}] {a.kind}: {a.message}")
