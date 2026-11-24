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
import json
import os
import re
import sys
import time

from llm_url_scan import decide as D
from llm_url_scan import judge, keys
from llm_url_scan import pagetext as PT

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
    def __init__(self, name, prompt, route_money=False):
        self.name, self.prompt, self.route_money = name, prompt, route_money


class Ledger:
    """Append-only jsonl. A call has a `reserve` line (run, reserved) and later a settle line (actual); an unsettled call counts at its reservation."""

    def __init__(self, path):
        self.path, self.calls = path, {}
        if os.path.exists(path):
            with open(path, encoding="utf-8") as f:
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

    def _append(self, r):
        with open(self.path, "a", encoding="utf-8") as f:
            f.write(json.dumps(r, sort_keys=True) + "\n")
        self._apply(r)

    def reserve(self, run, amount, run_cap, grand_cap):
        """Refuse when this run's total plus the reservation would pass `run_cap`, or the total over all runs would pass `grand_cap`."""
        if self.spent(run) + amount > run_cap + 1e-9:
            raise Refused("run")
        if self.spent() + amount > grand_cap + 1e-9:
            raise Refused("grand")
        call = "%d-%d" % (time.time_ns(), len(self.calls))
        self._append({"call": call, "run": run, "reserved": round(amount, 6), "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())})
        return call

    def settle(self, call, actual):
        self._append({"call": call, "actual": round(actual, 6)})


def page_sections(rec):
    """Saved HTML -> the five sections as the model gets them (final address = page address, status 200, no redirects)."""
    html = rec["html"]
    scan = PT.scan_page(html)
    page = PT.build_page(rec["url"], rec["url"], 200, 0, scan["title"], PT.html_to_text(html), scan, PT.extract_buttons(html), None)
    return judge.model_sections(rec["url"], page["sections"])


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
    sections = page_sections(rec)
    msg, info, quote_page = judge.build_message(sections)
    money = money_signal(sections)

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
    route = D.routed_because(h, short)
    money_route = route is None and arm.route_money and money
    if money_route:
        route = "money"
    s = call(judge.SONNET) if route else None
    d = D.decide(h, s, short or money_route)      # a money page is handled like a short page that Haiku passed
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
    """NAME=prompt_file or NAME=prompt_file+money."""
    name, _, rest = spec.partition("=")
    money = rest.endswith("+money")
    with open(rest[:-6] if money else rest, encoding="utf-8") as f:
        return Arm(name, f.read(), money)


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
