"""Replay saved pages through the service's own judge code, one result line per (page, arm, repeat).

Pages are built with the service's pagetext/judge/decide (no copy of that logic). An arm = a system prompt file plus an optional harness
routing option `route_money` (pages with a payment/checkout form or price text go to Sonnet even when Haiku passes; NOT a service change).
Result lines carry ids, labels, verdicts, rule codes, quote COUNTS, tokens, cost, decision and reason: never a URL, title or page text.
The model client is injected (`client.messages.create(**kw)`), so tests use a fake. The key is read only by main().

Usage: python -I -m evals.replay --pages-dir DIR --ids FILE --arm BASE=prompt.md --arm MONEY=prompt.md+money
         --run RUN1 --run-cap 4.0 --grand-cap 25 --ledger LEDGER.jsonl --out-dir OUT [--repeats 2]
Page files: DIR/<id>.json with url, html and label (the dataset URL label). ids file: one id per line.
"""
import argparse
import collections
import fcntl
import json
import os
import re
import sys
import time

from llm_url_scan import decide as D
from llm_url_scan import judge, keys
from llm_url_scan import pagetext as PT

try:      # the unchanged build (7dcf766) has no page-fact rules: replayed from there it is the old routing, nothing else
    from llm_url_scan import pagefacts as PF
except ImportError:
    PF = None

KEY_FILE = "/Users/haimengzhou/apps/secrets/anthropic-llm-url-scan.env"
KEY_VAR = "LLMURL_ANTHROPIC_API_KEY"
MAX_ERROR_RUN = 6      # this many final API errors in a row halt the run
MONEY_FORM = re.compile(r"card|cvv|cvc|expir|payment|checkout|billing|credit", re.I)
MONEY_PRICE = re.compile(r"[$€£¥]\s?\d|\b\d+(?:[.,]\d{2})?\s?(?:usd|eur|gbp)\b|\b(?:add to cart|buy now|checkout|free shipping)\b", re.I)


class Refused(Exception):
    """The ledger refused a reservation: args[0] is 'run' or 'grand'."""


class Halt(Exception):
    """An account-level failure or a run of API errors: every further call would fail."""


class Arm:
    """`legacy` = the unchanged service's decision (no could-not-scan detector, no shop routing); otherwise the changed one when the build has it."""

    def __init__(self, name, prompt, route_money=False, legacy=False):
        self.name, self.prompt, self.route_money, self.legacy = name, prompt, route_money, legacy


class Ledger:
    """Append-only jsonl. A call has a `reserve` line (run, reserved) and later a settle line (actual); an unsettled call counts at its reservation.
    Every write re-reads the file under an exclusive lock, so replays that share one ledger see each other's spend before reserving."""

    def __init__(self, path):
        self.path, self.calls = path, {}
        if os.path.exists(path):
            with open(path, encoding="utf-8") as f:
                self._reload(f)

    def _reload(self, f):
        f.seek(0)
        self.calls = {}
        for line in f:
            if line.strip():
                self._apply(json.loads(line))

    def _apply(self, r):
        c = self.calls.setdefault(r["call"], {"run": r.get("run"), "cost": 0.0})
        if "reserved" in r:
            c["run"], c["cost"] = r["run"], r["reserved"]
        if "actual" in r:
            c["cost"] = r["actual"]

    def spent(self, run=None):
        return round(sum(c["cost"] for c in self.calls.values() if run is None or c["run"] == run), 6)

    def _locked_append(self, make):
        """Lock, re-read, let `make()` check the totals and build the line (or raise), append it. -> the line."""
        with open(self.path, "a+", encoding="utf-8") as f:
            fcntl.flock(f, fcntl.LOCK_EX)      # released when the file closes
            self._reload(f)
            r = make()
            f.write(json.dumps(r, sort_keys=True) + "\n")
            f.flush()
            self._apply(r)
        return r

    def reserve(self, run, amount, run_cap, grand_cap):
        """Refuse when this run's total plus the reservation would pass `run_cap`, or the total over all runs would pass `grand_cap`."""
        def make():
            if self.spent(run) + amount > run_cap + 1e-9:
                raise Refused("run")
            if self.spent() + amount > grand_cap + 1e-9:
                raise Refused("grand")
            return {"call": "%d-%d" % (time.time_ns(), len(self.calls)), "run": run, "reserved": round(amount, 6),
                    "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}
        return self._locked_append(make)["call"]

    def settle(self, call, actual):
        self._locked_append(lambda: {"call": call, "actual": round(actual, 6)})


def raw_sections(rec):
    """Saved HTML -> the sections the capture hands the service (final address = page address, status 200, no redirects)."""
    html = rec["html"]
    scan = PT.scan_page(html)
    return PT.build_page(rec["url"], rec["url"], 200, 0, scan["title"], PT.html_to_text(html), scan, PT.extract_buttons(html), None)["sections"]


def page_sections(rec):
    """The sections as the model gets them."""
    return judge.model_sections(rec["url"], raw_sections(rec))


def money_signal(sections):
    """True when the forms block has a payment field or button, or the page text shows a price or a buy/checkout phrase."""
    return bool(MONEY_FORM.search(sections.get("page_forms", "")) or MONEY_PRICE.search(sections.get("page_text", "")))


def load_pages(pages_dir, ids_file):
    with open(ids_file, encoding="utf-8") as f:
        ids = sorted({x.strip() for x in f if x.strip()})
    for i in ids:
        with open(os.path.join(pages_dir, i + ".json"), encoding="utf-8") as f:
            rec = json.load(f)
        rec["id"] = i
        yield rec


def summary(rec):
    u = rec.get("usage", {})
    return {"model": rec.get("model") or None, "outcome": rec["outcome"], "reason": rec["reason"], "verdict": rec.get("verdict"), "rules": rec.get("rules", []),
            "quotes_total": rec.get("quotes_total", 0), "quotes_matched": rec.get("quotes_matched", 0), "in": u.get("input_tokens", 0),
            "out": u.get("output_tokens", 0), "cost": rec["cost_usd"], "attempts": rec.get("attempts", 1)}


def judge_page(rec, arm, client, ledger, run, run_cap, grand_cap, repeat, state):
    """One page, one arm: Haiku, then Sonnet by the service's routing (plus `route_money` when the arm asks), then the service's decision."""
    raw = raw_sections(rec)
    sections = judge.model_sections(rec["url"], raw)
    msg, info, quote_page = judge.build_message(sections)
    money = money_signal(sections)
    changed = PF is not None and not arm.legacy
    why = PF.could_not_scan_reason(raw) if changed else None      # the service's own detector, before any model call
    if why:
        return {"id": rec["id"], "arm": arm.name, "repeat": repeat, "run": run, "label": rec.get("label"), "decision": "could_not_scan",
                "judge_decision": "could_not_scan", "reason": why, "routed_because": None, "short": info["text_chars"] <= D.SHORT_CHARS, "money": money,
                "calls": [], "cost": 0.0}
    shop = bool(changed and PF.shop_signal(raw))

    def call(model):
        amount = judge.reservation([model], judge.input_bound(arm.prompt, msg))      # (1 + 1 retry) x the per-call worst case
        cid = ledger.reserve(run, amount, run_cap, grand_cap)
        r = judge.call_model(client, model, arm.prompt, msg, quote_page, info["empty_page"])
        ledger.settle(cid, r["cost_usd"])      # a failed or retried call is counted at its cost
        if r.get("stop_kind"):
            raise Halt(r["stop_kind"])
        state["err_run"] = state["err_run"] + 1 if r["outcome"] == "ERROR" else 0
        if state["err_run"] >= MAX_ERROR_RUN:
            raise Halt("errors")
        return r

    h = call(judge.HAIKU)
    short = info["text_chars"] <= D.SHORT_CHARS
    route = D.routed_because(h, short, shop) if shop else D.routed_because(h, short)
    money_route = route is None and arm.route_money and money
    if money_route:
        route = "money"
    s = call(judge.SONNET) if route else None
    d = D.decide(h, s, short or money_route, shop) if shop else D.decide(h, s, short or money_route)      # a money page is handled like a short page that Haiku passed
    reason = d["reason"].replace("_short", "_money") if money_route else d["reason"]
    recs = [r for r in (h, s) if r]
    return {"id": rec["id"], "arm": arm.name, "repeat": repeat, "run": run, "label": rec.get("label"), "decision": d["decision"],
            "judge_decision": d["decision"], "reason": reason, "routed_because": route, "short": short, "money": money,
            "calls": [summary(r) for r in recs], "cost": round(sum(r["cost_usd"] for r in recs), 6)}


def run_arms(pages, arms, client, ledger, run, run_cap, grand_cap, out_dir, repeats=1):
    """Arms and repeats interleaved page by page. A (page, arm, repeat) already in its result file is skipped. -> Counter."""
    os.makedirs(out_dir, exist_ok=True)
    path = {a.name: os.path.join(out_dir, "%s-%s.jsonl" % (run, a.name)) for a in arms}
    done = set()
    for name, p in path.items():
        if os.path.exists(p):
            with open(p, encoding="utf-8") as f:
                done |= {(r["id"], name, r["repeat"]) for r in map(json.loads, (x for x in f if x.strip()))}
    n, state = collections.Counter(), {"err_run": 0}
    for rec in pages:
        for repeat in range(repeats):
            for arm in arms:
                if (rec["id"], arm.name, repeat) in done:
                    n["skipped"] += 1
                    continue
                try:
                    line = judge_page(rec, arm, client, ledger, run, run_cap, grand_cap, repeat, state)
                except Refused as e:
                    n["stopped_ledger_" + e.args[0]] += 1
                    return n
                except Halt as e:
                    n["stopped_" + e.args[0]] += 1
                    return n
                with open(path[arm.name], "a", encoding="utf-8") as f:
                    f.write(json.dumps(line, sort_keys=True) + "\n")
                n["lines"] += 1
    return n


def parse_arm(spec):
    """NAME=prompt_file, optionally followed by +money and/or +legacy (the unchanged decision)."""
    name, _, rest = spec.partition("=")
    flags = set()
    while rest.endswith(("+money", "+legacy")):
        rest, _, flag = rest.rpartition("+")
        flags.add(flag)
    with open(rest, encoding="utf-8") as f:
        return Arm(name, f.read(), "money" in flags, "legacy" in flags)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--pages-dir", required=True)
    ap.add_argument("--ids", required=True)
    ap.add_argument("--arm", action="append", required=True)
    ap.add_argument("--run", required=True)
    ap.add_argument("--run-cap", type=float, required=True)
    ap.add_argument("--grand-cap", type=float, required=True)
    ap.add_argument("--ledger", required=True)
    ap.add_argument("--out-dir", required=True)
    ap.add_argument("--repeats", type=int, default=1)
    ap.add_argument("--key-file", default=KEY_FILE)
    a = ap.parse_args()
    bad = sorted(k for k in os.environ if k.upper().startswith("ANTHROPIC_") or any(w in k.upper() for w in ("_LOG", "CUSTOM_HEADERS", "PROXY", "KEYLOG")))
    if bad:
        sys.exit("BAD ENV (%d variable names)" % len(bad))
    arms = [parse_arm(s) for s in a.arm]
    pages = list(load_pages(a.pages_dir, a.ids))
    ledger = Ledger(a.ledger)
    client = judge.build_client(keys.read_env_value(a.key_file, KEY_VAR))      # the only key read, at run time
    n = run_arms(pages, arms, client, ledger, a.run, a.run_cap, a.grand_cap, a.out_dir, a.repeats)
    print("REPLAY run=%s pages=%d arms=%s repeats=%d %s" % (a.run, len(pages), ",".join(x.name for x in arms), a.repeats, " ".join("%s=%d" % kv for kv in sorted(n.items()))))
    print("SPENT %.4f RUN=%s" % (ledger.spent(a.run), a.run))
    print("SPENT %.4f TOTAL" % ledger.spent())
    sys.exit(3 if any(k.startswith("stopped") for k in n) else 0)


if __name__ == "__main__":
    main()
