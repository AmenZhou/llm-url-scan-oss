"""Spend ledger, circuit breakers and the Web Risk daily call counter. One SQLite file in the data dir.

A call RESERVES the worst case before any capture; the reservation is replaced by the measured cost. Reservations still open after a
restart stay charged. A cap hit or an open breaker refuses the call (503) with no decision.
"""
import os
import sqlite3
import threading
from datetime import datetime, timezone

_FMT = "%Y-%m-%dT%H:%M:%SZ"
# Breaker thresholds: the mean-cost breaker trips when the rolling mean cost per judged scan exceeds MEAN_FACTOR * PLAN_MEAN (0.01125 USD). PLAN_MEAN is the
# expected mean cost per judged scan. Typical cost per judged scan is under one cent; it depends on the traffic mix (how many pages go to the second model).
# Recalibrate PLAN_MEAN for your model and prices.
MIN_CALLS, WINDOW, BAD_RATE, MEAN_FACTOR, PLAN_MEAN = 20, 50, 0.10, 1.25, 0.009
FINAL_KINDS = ("shape400",)


class SpendCap(Exception):
    """A cap would be passed."""


class Ledger:
    def __init__(self, path, daily_cap, total_cap, run_cap=None, run_start=None, clock=lambda: datetime.now(timezone.utc)):
        self.daily_cap, self.total_cap, self.run_cap, self.run_start, self.clock = daily_cap, total_cap, run_cap, run_start, clock
        self.db = sqlite3.connect(path, check_same_thread=False)
        self.lock = threading.RLock()
        self.db.executescript(
            "CREATE TABLE IF NOT EXISTS spend (id INTEGER PRIMARY KEY, ts TEXT, day TEXT, reserved REAL, cost REAL);"
            "CREATE TABLE IF NOT EXISTS scans (id INTEGER PRIMARY KEY, cost REAL, refusal INT, parse_fail INT, max_tokens INT, api_error INT);"
            "CREATE TABLE IF NOT EXISTS breaker (kind TEXT PRIMARY KEY, since_scan INTEGER, open INT);"
            "CREATE TABLE IF NOT EXISTS wr_calls (day TEXT PRIMARY KEY, n INT);")
        self.db.commit()
        os.chmod(path, 0o600)

    def _day(self):
        return self.clock().strftime("%Y-%m-%d")

    def _used(self, where="", args=()):
        # settled rows count their measured cost, open rows their reservation
        return self.db.execute("SELECT COALESCE(SUM(CASE WHEN cost IS NULL THEN reserved ELSE cost END), 0) FROM spend WHERE 1=1 " + where, args).fetchone()[0]

    def _check(self, extra, exclude_id=-1):
        w, a = " AND id != ?", (exclude_id,)
        if self._used(w + " AND day = ?", a + (self._day(),)) + extra > self.daily_cap + 1e-9 or self._used(w, a) + extra > self.total_cap + 1e-9:
            raise SpendCap()
        if self.run_cap is not None and self._used(w + " AND ts >= ?", a + (self.run_start,)) + extra > self.run_cap + 1e-9:
            raise SpendCap()

    def reserve(self, amount):
        with self.lock:
            self._check(amount)
            cur = self.db.execute("INSERT INTO spend (ts, day, reserved, cost) VALUES (?,?,?,NULL)", (self.clock().strftime(_FMT), self._day(), amount))
            self.db.commit()
            return cur.lastrowid

    def topup(self, rid, amount):
        """Raise an open reservation to `amount` (never lowers it)."""
        with self.lock:
            cur = self.db.execute("SELECT reserved FROM spend WHERE id=? AND cost IS NULL", (rid,)).fetchone()
            if cur and amount > cur[0]:
                self._check(amount, exclude_id=rid)
                self.db.execute("UPDATE spend SET reserved=? WHERE id=?", (amount, rid))
                self.db.commit()

    def settle(self, rid, cost=None):
        """Replace the reservation by the measured cost (None = keep the reservation as the charge)."""
        with self.lock:
            self.db.execute("UPDATE spend SET cost = COALESCE(?, reserved) WHERE id=? AND cost IS NULL", (cost, rid))
            self.db.commit()

    def spent(self):
        """-> (today, total) including open reservations."""
        with self.lock:
            return round(self._used(" AND day = ?", (self._day(),)), 6), round(self._used(), 6)

    # ---------------------------------------------------------------- Web Risk daily ceiling
    def wr_allow(self, ceiling):
        with self.lock:
            n = (self.db.execute("SELECT n FROM wr_calls WHERE day=?", (self._day(),)).fetchone() or (0,))[0]
            if n >= ceiling:
                return False
            self.db.execute("INSERT INTO wr_calls (day, n) VALUES (?,1) ON CONFLICT(day) DO UPDATE SET n = n + 1", (self._day(),))
            self.db.commit()
            return True

    # ---------------------------------------------------------------- breakers
    def open_kinds(self):
        with self.lock:
            return [r[0] for r in self.db.execute("SELECT kind FROM breaker WHERE open=1")]

    def open_breaker(self, kind):
        with self.lock:
            self.db.execute("INSERT INTO breaker (kind, since_scan, open) VALUES (?, 0, 1) ON CONFLICT(kind) DO UPDATE SET open=1", (kind,))
            self.db.commit()

    def resume(self, kind, changed=False):
        """Owner only. A final kind needs a code or config change first (changed=True). The rolling window restarts after a resume."""
        if kind in FINAL_KINDS and not changed:
            return False
        with self.lock:
            last = self.db.execute("SELECT COALESCE(MAX(id), 0) FROM scans").fetchone()[0]
            cur = self.db.execute("UPDATE breaker SET open=0, since_scan=? WHERE kind=? AND open=1", (last, kind))
            self.db.commit()
            return cur.rowcount > 0

    def record_scan(self, cost, refusal, parse_fail, max_tokens, api_error):
        """One row per scan that ran a model. -> the breaker kinds this row opened (rolling last 50 scans, active from 20)."""
        with self.lock:
            self.db.execute("INSERT INTO scans (cost, refusal, parse_fail, max_tokens, api_error) VALUES (?,?,?,?,?)",
                            (cost, int(refusal), int(parse_fail), int(max_tokens), int(api_error)))
            self.db.commit()
            since = max([r[0] for r in self.db.execute("SELECT since_scan FROM breaker")] or [0])
            rows = self.db.execute("SELECT cost, refusal, parse_fail, max_tokens, api_error FROM scans WHERE id > ? ORDER BY id DESC LIMIT ?", (since, WINDOW)).fetchall()
            opened = []
            if len(rows) >= MIN_CALLS:
                n = len(rows)
                for kind, i in (("refusal_content", 1), ("parse_storm", 2), ("maxtok_storm", 3)):
                    if sum(r[i] for r in rows) / n > BAD_RATE:
                        opened.append(kind)
                if sum(r[0] for r in rows) / n > MEAN_FACTOR * PLAN_MEAN:
                    opened.append("meancost")
            if len(rows) >= 3 and all(r[4] for r in rows[:3]):
                opened.append("errors3")
            opened = [k for k in opened if k not in self.open_kinds()]
            for k in opened:
                self.open_breaker(k)
            return opened
