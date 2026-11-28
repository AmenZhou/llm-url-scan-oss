"""Replay two site-history rules over saved results, with no model calls and no network.

  known_site  registrable domain seen ONLY in phishing in the history -> hold a page the judge passed (domains on the shared-host list are skipped)
  tiebreak    judge "cannot tell" (reason hold_sonnet_cannot_tell) and the domain seen ONLY as good -> pass

History = labelled corpus pages (url, label, date). Default is time-ordered: only history pages dated BEFORE the judged page. `--history-mode all`
uses the whole corpus and the output is labelled "upper bound". Dataset-label history is a best case the live service cannot reach.
Output rows copy the result row with the new `decision`, `judge_decision` (the judge's own) and `rule`; they score like any arm (evals.score).

Usage: python -I -m evals.rules_replay --results R.jsonl --meta pages.jsonl --history corpus.jsonl|corpus-*.parquet --out OUT.jsonl
         [--rule known_site|tiebreak|both] [--history-mode time|all] [--no-exceptions] [--shared-hosts FILE] [--strata-out FILE]
meta: id, url, date of each judged page. history: url, label (phish|benign), date; a .parquet file needs pyarrow (columns url, label, date only are read).
"""
import argparse
import collections
import json
from urllib.parse import urlsplit

SECOND_LEVEL = {"co", "com", "org", "net", "gov", "ac", "edu", "or", "ne", "go"}
SHARED_HOSTS = {"github.io", "blogspot.com", "weebly.com", "wixsite.com", "herokuapp.com", "netlify.app", "pages.dev", "web.app", "firebaseapp.com",
                "000webhostapp.com", "sites.google.com", "wordpress.com", "glitch.me", "vercel.app", "workers.dev", "onrender.com", "azurewebsites.net"}


# domain helpers as in tmp/rag1-scripts/build_splits.py
def host_of(url):
    url = url or ""
    parts = urlsplit(url if "//" in url else "https://" + url)
    return (parts.hostname or "").lower(), ("//" not in url)


def registrable(host):
    labels = [x for x in host.split(".") if x]
    if len(labels) <= 2:
        return host
    if len(labels[-1]) == 2 and labels[-2] in SECOND_LEVEL:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def domain_of(url):
    return registrable(host_of(url)[0])


def day(date):
    return str(date)[:10] if date else None


def read_history(path):
    """-> [(url, label, date)] from jsonl or parquet."""
    if path.endswith(".parquet"):
        import pyarrow.parquet as pq      # only for the dataset's own files
        for batch in pq.ParquetFile(path).iter_batches(batch_size=1000, columns=["url", "label", "date"]):
            c = batch.to_pydict()
            yield from zip(c["url"], c["label"], c["date"])
        return
    with open(path, encoding="utf-8") as f:
        for x in f:
            if x.strip():
                r = json.loads(x)
                yield r["url"], r["label"], r.get("date")


class History:
    def __init__(self, rows):
        self.by_domain = collections.defaultdict(list)
        for url, label, date in rows:
            self.by_domain[domain_of(url)].append((day(date), label))

    def status(self, domain, date, mode):
        """unknown | phish_only | benign_only | mixed. Time mode: only history dated before `date` (a page with no date sees none)."""
        labels = {lab for d, lab in self.by_domain.get(domain, ()) if mode == "all" or (d and date and d < date)}
        return "unknown" if not labels else "phish_only" if labels == {"phish"} else "benign_only" if labels == {"benign"} else "mixed"


def replay(rows, meta, hist, rules=("known_site", "tiebreak"), mode="time", exceptions=SHARED_HOSTS):
    """-> (new result rows, {id: status}). Rows without meta are left untouched and get status unknown."""
    out, strata = [], {}
    for r in rows:
        m = meta.get(r["id"])
        new = dict(r, judge_decision=r.get("judge_decision", r["decision"]), history=mode)
        if m:
            host = host_of(m["url"])[0]
            dom = registrable(host)
            st = hist.status(dom, day(m.get("date")), mode)
            strata[r["id"]] = st
            # an exception may be a registrable domain (github.io) or a host below one (sites.google.com)
            shared = dom in exceptions or any(host == e or host.endswith("." + e) for e in exceptions)
            if "known_site" in rules and st == "phish_only" and r["decision"] == "pass" and not shared:
                new.update(decision="hold", rule="known_site")
            elif "tiebreak" in rules and st == "benign_only" and r.get("reason") == "hold_sonnet_cannot_tell":
                new.update(decision="pass", rule="tiebreak")
        else:
            strata[r["id"]] = "unknown"
        out.append(new)
    return out, strata


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--results", required=True)
    ap.add_argument("--meta", required=True)
    ap.add_argument("--history", action="append", required=True)
    ap.add_argument("--rule", choices=("known_site", "tiebreak", "both"), default="both")
    ap.add_argument("--history-mode", choices=("time", "all"), default="time")
    ap.add_argument("--no-exceptions", action="store_true")
    ap.add_argument("--shared-hosts")
    ap.add_argument("--out", required=True)
    ap.add_argument("--strata-out")
    a = ap.parse_args()
    with open(a.results, encoding="utf-8") as f:
        rows = [json.loads(x) for x in f if x.strip()]
    with open(a.meta, encoding="utf-8") as f:
        meta = {r["id"]: r for r in map(json.loads, (x for x in f if x.strip()))}
    exceptions = set() if a.no_exceptions else SHARED_HOSTS
    if a.shared_hosts and not a.no_exceptions:
        with open(a.shared_hosts, encoding="utf-8") as f:
            exceptions = {x.strip() for x in f if x.strip()}
    hist = History(r for p in a.history for r in read_history(p))
    rules = ("known_site", "tiebreak") if a.rule == "both" else (a.rule,)
    new, strata = replay(rows, meta, hist, rules, a.history_mode, exceptions)
    with open(a.out, "w", encoding="utf-8") as f:
        f.write("".join(json.dumps(r, sort_keys=True) + "\n" for r in new))
    if a.strata_out:
        with open(a.strata_out, "w", encoding="utf-8") as f:
            f.write("".join(json.dumps({"id": i, "status": s}) + "\n" for i, s in sorted(strata.items())))
    print("HISTORY %s%s exceptions=%d rules=%s" % ("time-ordered" if a.history_mode == "time" else "all pages (upper bound)",
                                                 "" if a.history_mode == "all" else " (still a dataset upper bound: labelled history)", len(exceptions), ",".join(rules)))
    c = collections.Counter((r["label"], r["rule"]) for r in new if r.get("rule"))
    for (label, rule), k in sorted(c.items()):
        print("RULE %s changed %d pages with url_label=%s" % (rule, k, label))
    print("STATUS " + " ".join("%s=%d" % kv for kv in sorted(collections.Counter(strata.values()).items())))


if __name__ == "__main__":
    main()
