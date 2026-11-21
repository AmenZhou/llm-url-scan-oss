"""Weekly counts report. Reads only the log, never the store.

Output is counts and fixed words only: every line passes the leak guard with a vocabulary of the log's enums plus the words of
this file's own templates; one failing token aborts the report. No id is printed, not even a prefix.
"""
import json
import math
import re
import statistics
from datetime import date, datetime
from pathlib import Path

from .logs import VOCAB, check_text

DECISION_4 = "No person reviews pages: Web Risk on day 0 and day 7 is the only independent signal."
RULES = (
    "1. False holds are an upper bound apart from Web Risk listing errors: no person labels pages, so a hold that Web Risk does not list "
    "is unconfirmed, never false; the false-hold share is at most unconfirmed holds divided by readable pages, printed per caller "
    "above; it is not a false-positive rate.",
    "2. Catch beyond Web Risk is not shown: a hold that Web Risk lacks is not a catch; the report states agreement with Web Risk, not accuracy.",
    "3. Web Risk positive means the address is listed; negative does not mean safe; day 0 can come before a listing, "
    "day 7 is the better independent signal and is still incomplete.",
    "4. Unreadable pages are held by policy; they are counted apart, and the hold rate is printed with and without them.",
    "5. No outside reference figures are printed in this report; overlaps use readable pages only, and unreadable holds have their own block.",
    "6. No percentage is printed for a group under 30 pages; counts only.",
    "7. Agreement of the judge with Web Risk is consistent, not independent.",
    "8. Ids are counted per salt version; one address scanned under two versions counts twice.",
    "9. The model sees the address without its query string; "
    "a judge that saw the full address could answer differently.",
)
LABELS = ("llm-url-scan weekly counts report week volume calls answered refusals readable unreadable unreadable_detail range "
          "haiku sonnet state reason routed route overrode turned to hold pass d1a decision holds excluding hold_rate with without "
          "web_risk d0 d7 pending overlaps unconfirmed misses alone patterns injection truncated recheck6 rechecked skipped became decidable "
          "cost spend_usd per_1000_readable_usd sonnet_share_readable spend_cap_refusals latency median p95 capture_s haiku_s sonnet_s total_s "
          "health breaker salt_ver api_error outage n/a reading rules p05 p12 p13 p15 distinct ids of upper bound not a false-positive rate "
          "caller unreadable_holds")
REPORT_VOCAB = VOCAB | {w.strip("[](),:;|") for w in (LABELS + " " + DECISION_4 + " " + " ".join(RULES)).split()}


def load(data_dir):
    out = []
    for p in sorted(Path(data_dir).glob("scan-*.jsonl")):
        out += [json.loads(l) for l in p.read_text(encoding="ascii").splitlines() if l.strip()]
    return out


def _week(ts):
    y, w, _ = datetime.strptime(ts[:10], "%Y-%m-%d").isocalendar()
    return y, w


def _pct(a, b):
    return "%.1f%%" % (100.0 * a / b) if b >= 30 else "n/a"


def _p95(xs):
    return sorted(xs)[math.ceil(0.95 * len(xs)) - 1]


def build(events, year, week):
    wk = [e for e in events if _week(e["ts"]) == (year, week)]
    scans = [e for e in wk if e["event"] == "scan"]
    d7 = {(e["salt_ver"], e["hid"]): e["wr_d7"] for e in events if e["event"] == "recheck"}
    r6 = {(e["salt_ver"], e["hid"]): e for e in events if e["event"] == "recheck6"}
    key = lambda s: (s["salt_ver"], s["hid"])      # noqa: E731
    out = []
    say = lambda *parts: out.append(" ".join(str(p) for p in parts))      # noqa: E731

    def tally(label, rows, field):
        for v in sorted({r.get(field) for r in rows if r.get(field) is not None}, key=str):
            say(label, v, sum(r.get(field) == v for r in rows))

    readable = [s for s in scans if s["readable"]]
    unread = [s for s in scans if not s["readable"]]
    holds = [s for s in scans if s["decision"] == "hold"]
    say("llm-url-scan weekly counts report week", year, week)
    say(DECISION_4)
    say("[volume]")
    say("calls answered", len(scans), "distinct ids", len({key(s) for s in scans}))
    tally("salt_ver", scans, "salt_ver")
    tally("refusals", [e for e in wk if e["event"] == "refusal"], "code")
    say("readable", len(readable))
    say("unreadable", len(unread))
    tally("unreadable", unread, "unreadable_reason")
    tally("unreadable_detail", unread, "unreadable_detail")
    tally("proxy_refused range", unread, "range_class")

    say("[haiku]")
    tally("haiku state", readable, "h_state")
    tally("haiku reason", readable, "h_reason")
    say("[sonnet]")
    routed = [s for s in scans if s.get("s_routed_because")]
    say("sonnet routed", len(routed))
    tally("sonnet route", routed, "s_routed_because")
    tally("sonnet state", routed, "s_state")
    say("haiku HOLD overrode to pass", sum(s.get("h_state") == "HOLD" and s["decision"] == "pass" for s in scans))
    say("haiku PASS turned to hold", sum(s.get("h_state") == "PASS" and s["decision"] == "hold" for s in scans))

    say("[d1a]")
    tally("d1a decision", scans, "decision")
    tally("d1a holds reason", holds, "reason")
    say("d1a holds excluding unreadable", len(holds) - len(unread))
    say("hold_sonnet_failed api_error outage", sum(s["reason"] == "hold_sonnet_failed" and s.get("s_reason") == "api_error" for s in scans))
    say("hold_rate with unreadable", _pct(len(holds), len(scans)))
    say("hold_rate without unreadable", _pct(len(holds) - len(unread), len(readable)))

    say("[web_risk]")
    tally("web_risk d0", scans, "wr_d0")
    for v in ("positive", "negative", "error", "missed_window", "missed_key"):
        say("web_risk d7", v, sum(d7.get(key(s)) == v for s in scans))
    say("web_risk d7 pending", sum(key(s) not in d7 for s in scans))

    say("[overlaps]")      # readable pages only
    pos0 = lambda s: s.get("wr_d0") == "positive"          # noqa: E731
    pos7 = lambda s: d7.get(key(s)) == "positive"          # noqa: E731
    unconfirmed = lambda s: s["decision"] == "hold" and not pos0(s) and not pos7(s)      # noqa: E731
    for who, is_hold in (("d1a", lambda s: s["decision"] == "hold"), ("haiku alone", lambda s: s.get("h_state") != "PASS")):
        say(who, "hold web_risk d0 positive", sum(is_hold(s) and pos0(s) for s in readable))
        say(who, "hold web_risk d7 positive", sum(is_hold(s) and pos7(s) for s in readable))
        say(who, "unconfirmed holds", sum(is_hold(s) and not pos0(s) and not pos7(s) for s in readable))
        say(who, "misses pass web_risk positive", sum(not is_hold(s) and (pos0(s) or pos7(s)) for s in readable))
    for c in sorted({s["caller"] for s in readable}):      # rule 1 with its denominator, per caller
        rc = [s for s in readable if s["caller"] == c]
        n = sum(unconfirmed(s) for s in rc)
        say("caller", c, "unconfirmed holds", n, "of", len(rc), "readable", _pct(n, len(rc)), "upper bound not a false-positive rate")
    say("[unreadable_holds]")
    say("unreadable_holds", len(unread), "web_risk d0 positive", sum(pos0(s) for s in unread), "web_risk d7 positive", sum(pos7(s) for s in unread))

    say("[patterns]")
    for p in ("p05", "p12", "p13"):
        hit = [s for s in scans if s.get(p) == 1]
        say(p, len(hit), "holds", sum(s["decision"] == "hold" for s in hit))
    for v in ("under40", "thin", "longer"):
        hit = [s for s in scans if s.get("p15") == v]
        say("p15", v, len(hit), "holds", sum(s["decision"] == "hold" for s in hit))

    say("[injection]")
    say("haiku PASS injection", sum(s.get("h_state") == "PASS" and s.get("h_injection") is True for s in scans))
    say("sonnet PASS injection", sum(s.get("s_state") == "PASS" and s.get("s_injection") is True for s in scans))
    say("d1a pass injection", sum(s["decision"] == "pass" and (s.get("h_injection") or s.get("s_injection")) is True for s in scans))
    say("d1a pass truncated", sum(s["decision"] == "pass" and s.get("truncated") is True for s in scans))

    say("[recheck6]")
    first = [s for s in scans if s["reason"].startswith("unreadable_") or s["reason"] == "hold_sonnet_cannot_tell"]
    done = [r6[key(s)] for s in first if key(s) in r6 and not r6[key(s)]["r6_skipped"]]
    say("recheck6 rechecked", len(done), "skipped", sum(key(s) in r6 and r6[key(s)]["r6_skipped"] for s in first),
        "pending", sum(key(s) not in r6 for s in first))
    say("recheck6 became readable", sum(r.get("r6_readable") is True for r in done))
    say("recheck6 became decidable", sum(r.get("r6_d1a_state") in ("PASS", "HOLD") for r in done))
    say("recheck6 pass", sum(r.get("r6_d1a_state") == "PASS" for r in done), "hold", sum(r.get("r6_d1a_state") != "PASS" for r in done))

    say("[cost]")
    spent = sum(s.get("cost_usd", 0) for s in scans) + sum(r.get("r6_cost_usd", 0) for r in done)
    say("cost spend_usd", "%.4f" % spent)
    say("cost per_1000_readable_usd", "%.4f" % (1000 * sum(s.get("cost_usd", 0) for s in readable) / len(readable)) if readable else "n/a")
    say("cost sonnet_share_readable", _pct(sum(bool(s.get("s_routed_because")) for s in readable), len(readable)))
    say("cost spend_cap_refusals", sum(e["event"] == "refusal" and e["code"] == "spend_cap" for e in wk))

    say("[latency]")
    for label, xs in (("capture_s", [s["capture_ms"] / 1000 for s in scans if s.get("capture_ms") is not None]),
                      ("haiku_s", [s["h_latency_s"] for s in scans if s.get("h_latency_s") is not None]),
                      ("sonnet_s", [s["s_latency_s"] for s in scans if s.get("s_latency_s") is not None]),
                      ("total_s", [s["latency_ms"] / 1000 for s in scans if s.get("latency_ms") is not None])):
        say("latency", label, "median", "%.1f" % statistics.median(xs) if xs else "n/a", "p95", "%.1f" % _p95(xs) if xs else "n/a")

    say("[health]")
    br = [e for e in wk if e["event"] == "breaker"]
    for k in sorted({(e["kind"], e["state"]) for e in br}):
        say("breaker", k[0], k[1], sum((e["kind"], e["state"]) == k for e in br))
    say("[reading rules]")
    out += RULES
    text = "\n".join(out) + "\n"
    if check_text(text, REPORT_VOCAB | {s["caller"] for s in scans}):      # caller labels are owner-set token names, not page data
        raise ValueError("report line failed the leak guard")      # no content in the message
    return text


def this_week(today=None):
    y, w, _ = (today or date.today()).isocalendar()
    return y, w


def parse_week(s):
    """'2026-W47' -> (2026, 47)."""
    m = re.fullmatch(r"(\d{4})-W(\d{1,2})", s)
    if not m:
        raise ValueError("week format is YYYY-Www")
    return int(m.group(1)), int(m.group(2))
