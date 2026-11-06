"""
login_rate_limiter.py -- Multi-Login Frequency & Thresholding

Objective
---------
Mitigate brute-force and credential-spraying attacks by enforcing strict
rate-limit caps and behavioural validation rules on high-frequency,
multi-source login attempts.

Attack patterns covered (each has its own sliding-window counter)
  1. Per-IP volume        too many attempts from one IP        -> throttle, then block
  2. Per-account bruting  too many failures against one user   -> throttle, then lock
       (if the failures come from 3+ IPs it is labelled "distributed")
  3. Credential spraying  one IP failing across many usernames -> block
       (slow-and-low per account, so per-account limits never trip)
  4. Global surge         total failures spike across the service -> alert only

Enforcement model
-----------------
  verdict = limiter.precheck(ip, username)      # before verifying the password
  if verdict.decision == Decision.BLOCK: reject (HTTP 429, retry_after_s)
  ...verify credentials...
  verdict = limiter.record_attempt(ip, username, success)

Hard limits create a lockout with exponential backoff (60 s, 120 s, 240 s ...
capped), so repeat offenders are punished progressively while a legitimate
user who fat-fingers a password is back quickly. Keep calling
record_attempt() for rejected requests too: lockouts are not extended while
active, but the attacker stays visible in the counters.

Limits
------
State is in-memory per process. For multiple workers, back the dictionaries
with Redis or your SQLite layer. Thresholds are starting points; tune them
to your own traffic.
"""
from __future__ import annotations

import threading
import time
from collections import deque
from dataclasses import dataclass, field
from enum import Enum
from typing import Deque, Dict, List, Optional, Tuple


@dataclass
class Alert:
    """Common alert shape (move to a shared module if you prefer)."""
    detector: str
    identity: str
    severity: str
    kind: str
    message: str
    timestamp: float
    details: dict = field(default_factory=dict)


class Decision(str, Enum):
    ALLOW = "allow"
    THROTTLE = "throttle"     # allowed, but slow the client down (retry_after_s)
    BLOCK = "block"           # reject outright


@dataclass
class Verdict:
    decision: Decision = Decision.ALLOW
    retry_after_s: float = 0.0
    alerts: List[Alert] = field(default_factory=list)


@dataclass
class RateLimitConfig:
    ip_window_s: float = 60.0
    ip_soft_limit: int = 5            # attempts per window -> throttle
    ip_hard_limit: int = 10           # attempts per window -> block

    user_window_s: float = 300.0
    user_soft_limit: int = 5          # failures per window -> throttle
    user_hard_limit: int = 10         # failures per window -> lock account
    distributed_min_ips: int = 3      # failures from >= this many IPs = distributed

    spray_window_s: float = 300.0
    spray_distinct_users: int = 8     # distinct usernames failed by one IP

    global_window_s: float = 60.0
    global_fail_limit: int = 100      # service-wide failures per window -> alert

    lockout_base_s: float = 60.0
    lockout_max_s: float = 3600.0
    strike_decay_s: float = 86400.0   # forget past strikes after a quiet day
    throttle_step_s: float = 2.0      # delay grows per attempt over the soft limit
    throttle_max_s: float = 30.0
    alert_cooldown_s: float = 60.0


@dataclass
class _Lockout:
    until: float
    strikes: int


def _trim(q: Deque, cutoff: float, key=lambda x: x) -> None:
    """Pop entries older than cutoff from the left (deques are time-ordered)."""
    while q and key(q[0]) < cutoff:
        q.popleft()


class LoginRateLimiter:
    name = "login_rate_limiter"

    def __init__(self, config: Optional[RateLimitConfig] = None) -> None:
        self.cfg = config or RateLimitConfig()
        self._ip_attempts: Dict[str, Deque[float]] = {}
        self._user_fails: Dict[str, Deque[Tuple[float, str]]] = {}     # (ts, ip)
        self._ip_fail_users: Dict[str, Deque[Tuple[float, str]]] = {}  # (ts, username)
        self._global_fails: Deque[float] = deque()
        self._lockouts: Dict[Tuple[str, str], _Lockout] = {}           # ("ip"|"user", key)
        self._last_alert: Dict[Tuple[str, str], float] = {}
        self._lock = threading.Lock()

    # ------------------------------------------------------------------ API
    def precheck(self, ip: str, username: str, ts: Optional[float] = None) -> Verdict:
        """Call BEFORE verifying credentials. Does not modify counters."""
        ts = time.time() if ts is None else ts
        username = self._norm(username)
        with self._lock:
            wait = 0.0
            for key in (("ip", ip), ("user", username)):
                lk = self._lockouts.get(key)
                if lk and lk.until > ts:
                    wait = max(wait, lk.until - ts)
            if wait > 0:
                return Verdict(Decision.BLOCK, wait)

            ip_n = self._count(self._ip_attempts.get(ip), ts - self.cfg.ip_window_s)
            usr_n = self._count(self._user_fails.get(username), ts - self.cfg.user_window_s,
                                key=lambda x: x[0])
            over = max(ip_n - self.cfg.ip_soft_limit, usr_n - self.cfg.user_soft_limit)
            if over >= 0:
                delay = min(self.cfg.throttle_step_s * (over + 1), self.cfg.throttle_max_s)
                return Verdict(Decision.THROTTLE, delay)
            return Verdict()

    def record_attempt(self, ip: str, username: str, success: bool,
                       ts: Optional[float] = None) -> Verdict:
        """Call AFTER a login attempt. Updates counters, may raise lockouts/alerts."""
        ts = time.time() if ts is None else ts
        username = self._norm(username)
        c = self.cfg
        alerts: List[Alert] = []
        newly_locked = False

        with self._lock:
            # 1. per-IP volume (every attempt counts, success or not)
            ipq = self._ip_attempts.setdefault(ip, deque())
            ipq.append(ts)
            _trim(ipq, ts - c.ip_window_s)
            ip_n = len(ipq)

            if success:
                self._user_fails.pop(username, None)      # normal recovery path
            else:
                uq = self._user_fails.setdefault(username, deque())
                uq.append((ts, ip))
                _trim(uq, ts - c.user_window_s, key=lambda x: x[0])

                sq = self._ip_fail_users.setdefault(ip, deque())
                sq.append((ts, username))
                _trim(sq, ts - c.spray_window_s, key=lambda x: x[0])

                self._global_fails.append(ts)
                _trim(self._global_fails, ts - c.global_window_s)

            # ---- threshold evaluation -----------------------------------
            if ip_n >= c.ip_hard_limit:
                newly_locked |= self._lockout(("ip", ip), ts)
                alerts.append(Alert(self.name, ip, "high", "ip_rate_limit_exceeded",
                    f"{ip} made {ip_n} login attempts in {c.ip_window_s:.0f}s "
                    f"(limit {c.ip_hard_limit})", ts, {"attempts": ip_n}))

            if not success:
                uq = self._user_fails[username]
                if len(uq) >= c.user_hard_limit:
                    ips = {i for _, i in uq}
                    newly_locked |= self._lockout(("user", username), ts)
                    dist = len(ips) >= c.distributed_min_ips
                    alerts.append(Alert(self.name, username,
                        "critical" if dist else "high",
                        "distributed_brute_force" if dist else "account_brute_force",
                        f"{len(uq)} failed logins for '{username}' in {c.user_window_s:.0f}s "
                        f"from {len(ips)} IP(s)", ts,
                        {"failures": len(uq), "distinct_ips": len(ips)}))

                users = {u for _, u in self._ip_fail_users[ip]}
                if len(users) >= c.spray_distinct_users:
                    newly_locked |= self._lockout(("ip", ip), ts)
                    alerts.append(Alert(self.name, ip, "high", "credential_spraying",
                        f"{ip} failed logins against {len(users)} different usernames "
                        f"in {c.spray_window_s:.0f}s", ts, {"distinct_usernames": len(users)}))

                if len(self._global_fails) >= c.global_fail_limit:
                    alerts.append(Alert(self.name, "global", "medium", "global_failure_surge",
                        f"{len(self._global_fails)} failed logins service-wide in "
                        f"{c.global_window_s:.0f}s", ts,
                        {"failures": len(self._global_fails)}))

            alerts = self._cooldown(alerts)

            # ---- decision -----------------------------------------------
            if newly_locked or self._is_locked(ip, username, ts):
                wait = max((lk.until - ts for k, lk in self._lockouts.items()
                            if k in (("ip", ip), ("user", username)) and lk.until > ts),
                           default=0.0)
                return Verdict(Decision.BLOCK, wait, alerts)
            soft = (ip_n >= c.ip_soft_limit or
                    (not success and len(self._user_fails.get(username, ())) >= c.user_soft_limit))
            if soft:
                return Verdict(Decision.THROTTLE, c.throttle_step_s, alerts)
            return Verdict(Decision.ALLOW, 0.0, alerts)

    def unlock(self, kind: str, key: str) -> bool:
        """Admin override. kind is 'ip' or 'user'."""
        with self._lock:
            return self._lockouts.pop((kind, self._norm(key) if kind == "user" else key), None) is not None

    def purge(self, now: Optional[float] = None) -> None:
        """Free memory for idle keys. Call periodically (e.g. every minute)."""
        now = time.time() if now is None else now
        c = self.cfg
        with self._lock:
            for d, win, key in ((self._ip_attempts, c.ip_window_s, lambda x: x),
                                (self._user_fails, c.user_window_s, lambda x: x[0]),
                                (self._ip_fail_users, c.spray_window_s, lambda x: x[0])):
                for k in list(d):
                    _trim(d[k], now - win, key)
                    if not d[k]:
                        del d[k]
            _trim(self._global_fails, now - c.global_window_s)
            self._lockouts = {k: v for k, v in self._lockouts.items()
                              if v.until + c.strike_decay_s > now}

    # ------------------------------------------------------------- internals
    @staticmethod
    def _norm(username: str) -> str:
        return (username or "").strip().lower()

    @staticmethod
    def _count(q: Optional[Deque], cutoff: float, key=lambda x: x) -> int:
        if not q:
            return 0
        return sum(1 for x in q if key(x) >= cutoff)

    def _is_locked(self, ip: str, username: str, ts: float) -> bool:
        return any((lk := self._lockouts.get(k)) and lk.until > ts
                   for k in (("ip", ip), ("user", username)))

    def _lockout(self, key: Tuple[str, str], ts: float) -> bool:
        """Start (or escalate) a lockout. Returns True only if a NEW one began."""
        c = self.cfg
        existing = self._lockouts.get(key)
        if existing and existing.until > ts:
            return False                     # already locked: don't stack strikes
        strikes = 1
        if existing and ts - existing.until < c.strike_decay_s:
            strikes = existing.strikes + 1   # repeat offender: back off harder
        duration = min(c.lockout_base_s * 2 ** (strikes - 1), c.lockout_max_s)
        self._lockouts[key] = _Lockout(ts + duration, strikes)
        return True

    def _cooldown(self, alerts: List[Alert]) -> List[Alert]:
        out = []
        for a in alerts:
            key = (a.kind, a.identity)
            last = self._last_alert.get(key)
            if last is None or a.timestamp - last >= self.cfg.alert_cooldown_s:
                self._last_alert[key] = a.timestamp
                out.append(a)
        return out


# ------------------------------------------------------------------- demo
if __name__ == "__main__":
    lim = LoginRateLimiter()
    t = 1_700_000_000.0

    def attempt(ip, user, ok, ts):
        """Record an attempt and print any alerts the moment they fire."""
        v = lim.record_attempt(ip, user, ok, ts)
        for a in v.alerts:
            print(f"   [{a.severity}] {a.kind}: {a.message}")
        return v

    print("-- brute force: one IP hammering one account")
    for i in range(11):
        v = attempt("198.51.100.7", "admin", False, t + i)
    print(f"   verdict: {v.decision.value}, retry in {v.retry_after_s:.0f}s")
    p = lim.precheck("198.51.100.7", "admin", t + 16)
    print(f"   precheck 5s later: {p.decision.value}, retry in {p.retry_after_s:.0f}s")

    print("-- credential spraying: one IP, many usernames, 1 try each")
    for i in range(9):
        v = attempt("198.51.100.9", f"user{i}", False, t + 100 + i * 5)
    print(f"   verdict: {v.decision.value}")

    print("-- distributed brute force: 10 IPs, one account")
    for i in range(10):
        v = attempt(f"192.0.2.{i + 10}", "ceo", False, t + 300 + i)
    print(f"   verdict: {v.decision.value}")

    print("-- legitimate user: 1 typo then success")
    attempt("203.0.113.5", "priya", False, t + 600)
    v = attempt("203.0.113.5", "priya", True, t + 610)
    print(f"   verdict: {v.decision.value}")
