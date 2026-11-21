"""The scheduler's jobs: the day-7 Web Risk recheck and the one 6 h recheck of unknown pages.

`run_once` is one pass; `recheck-loop` repeats it. Addresses come only from the sealed store and are never logged; every log line
holds the hash id. The scheduler has the private store key but not the salt. The 6 h recheck itself runs in the API
(`/internal/recheck6`), which has the capture route and the model key; the scheduler only hands it the address.
"""
import json
import sys
import time
import urllib.request
from datetime import datetime, timedelta, timezone

_FMT = "%Y-%m-%dT%H:%M:%SZ"
D7_START, D7_END, HARD_DAYS = timedelta(days=7), timedelta(days=8), 10   # check from day 7; missed after day 8; hard delete at 10 days
R6_START, R6_END = timedelta(hours=5), timedelta(hours=7)                 # about 6 h, plus or minus 1
EVERY_S = 600      # a pass every 10 min keeps every row inside its 6 h window


def _t(s):
    return datetime.strptime(s, _FMT).replace(tzinfo=timezone.utc)


def run_once(store, webrisk, log, now, r6):
    """One pass. r6(url, hid, salt_ver) -> True when the API took the 6 h recheck. -> counts (numbers only)."""
    n = dict(d7=0, d7_missed=0, d7_missed_key=0, r6=0, r6_skipped=0)
    for hid, ver in store.purge_older(now, HARD_DAYS):      # safety net: normally a row is gone by day 8
        log.write("recheck", hid=hid, salt_ver=ver, wr_d7="missed_window", age_days=HARD_DAYS, wr_attempts=0)
        n["d7_missed"] += 1
    for hid, ver, _due, r6_due, created in store.rows():
        age = now - _t(created)
        if r6_due and age >= R6_START:
            done = False
            if age <= R6_END:
                try:
                    done = r6(store.read(hid, ver), hid, ver)
                except Exception:       # key lost or API down: retried next pass while the window lasts
                    done = False
            if done:
                store.clear_r6(hid, ver)
                n["r6"] += 1
            elif age > R6_END:
                log.write("recheck6", hid=hid, salt_ver=ver, r6_skipped=True)
                store.clear_r6(hid, ver)
                n["r6_skipped"] += 1
        if age < D7_START:
            continue
        if age > D7_END:
            log.write("recheck", hid=hid, salt_ver=ver, wr_d7="missed_window", age_days=age.days, wr_attempts=0)
            store.delete(hid, ver)
            n["d7_missed"] += 1
            continue
        try:
            url = store.read(hid, ver)
        except Exception:
            log.write("recheck", hid=hid, salt_ver=ver, wr_d7="missed_key", age_days=age.days, wr_attempts=0)
            store.delete(hid, ver)
            n["d7_missed_key"] += 1
            continue
        st = webrisk.check(url)
        if st == "not_checked":         # daily ceiling reached (or no key): try again next pass, until day 8
            continue
        log.write("recheck", hid=hid, salt_ver=ver, wr_d7=st, age_days=age.days, wr_attempts=getattr(webrisk, "attempts", 1))
        store.delete(hid, ver)
        n["d7"] += 1
    return n


def api_r6(base_url, token, timeout=450):
    """The scheduler's 6 h hand-off to the API's internal path. No proxy from the environment; the answer body is not read."""
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))

    def call(url, hid, salt_ver):
        req = urllib.request.Request(base_url + "/internal/recheck6", method="POST",
                                     data=json.dumps({"url": url, "hid": hid, "salt_ver": salt_ver}).encode("utf-8"),
                                     headers={"Authorization": "Bearer " + token, "Content-Type": "application/json"})
        try:
            with opener.open(req, timeout=timeout) as r:
                return r.status == 200
        except Exception:
            return False
    return call


def loop(store, webrisk, log, r6, clock=lambda: datetime.now(timezone.utc), sleep=time.sleep, every=EVERY_S):
    while True:
        try:
            n = run_once(store, webrisk, log, clock(), r6)
            print(" ".join("%s=%d" % kv for kv in sorted(n.items())))
        except Exception as e:      # class name only
            print("pass error %s" % type(e).__name__, file=sys.stderr)
        sleep(every)
