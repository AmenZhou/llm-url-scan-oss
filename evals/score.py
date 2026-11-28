"""Score replay results against graded labels. Prints COUNTS only: never a URL, host, title or page text.

Inputs (jsonl, one object per line)
  results   --results NAME=path (repeat for each arm; first arm is the baseline). Lines of evals/replay.py or rules_replay.py; older
            lines of tmp/rag1 need only id, decision, label, cost. With --repeats in the file, repeat 0 feeds the tables, flips are counted.
  labels    --labels path: id, url_label (phish|benign), kind, visible, grade (Gold|Silver|Bronze|none), judge_expect (hold|pass|either),
            system_expect, group (visible = sorted visible-lure group | urlset = unsorted URL-label phishing group | good), ptype (optional: form|shop|other)
            Without --labels the dataset label in the results is used and every phishing page counts as the whole-service group.
  strata    --strata path: id, status (unknown|phish_only|benign_only|mixed), as written by rules_replay.py --strata-out

Pools: false holds = every page with url_label benign (O3); whole-service catch = group urlset phishing pages; visible catch (per kind) =
group visible, grade Gold or Silver. Paired comparisons X vs Y use the PREREG.md tests (exact McNemar, Holm over the pairs, Newcombe paired
interval with the phi correction). Decision rule by --rule: a = five-verdict lower-holds rule (PREREG section 5), b = raise-holds holdout rule
(named catch up by Holm-adjusted McNemar; guard: upper bound of the paired false-hold increase <= G points), c = L2 carry rule.
"""
import argparse
import collections
import json
import sys

from evals.stats import holm, mcnemar_exact, paired_interval, wilson

ALPHA, GUARD_A, COST_LIMIT = 0.05, -0.05, 1.25
SURE = ("Gold", "Silver")


# ---------------------------------------------------------------- decision rules (booleans in, verdict out)
def verdict_a(fh_up, fh_down, catch_down, guard_met):
    """The pre-registered five-verdict rule, in its stated order (lower-holds candidates)."""
    if fh_up:
        return "shown worse"
    if catch_down:
        return "trade-off" if fh_down else "shown worse"
    if fh_down:
        return "shown better" if guard_met else "better on holds, catch not assured"
    return "not shown different"


def verdict_b(fh_up, catch_up, catch_down, guard_met):
    """Raise-holds holdout rule: named catch up is the main measure; guard = false-hold increase upper bound <= G."""
    if catch_down or fh_up:
        return "shown worse"
    if catch_up:
        return "shown better" if guard_met else "better on catch, holds not assured"
    return "not shown different"


def verdict_c(catch_up, fh_not_higher, cost_ok):
    """L2 carry rule: -> (carry?, failing conditions)."""
    failing = [n for n, ok in (("named catch not shown up", catch_up), ("false-hold count higher than baseline", fh_not_higher), ("cost ratio above 1.25", cost_ok)) if not ok]
    return not failing, failing


# ---------------------------------------------------------------- loading
def read_jsonl(path):
    with open(path, encoding="utf-8") as f:
        return [json.loads(x) for x in f if x.strip()]


def load_arms(specs):
    """specs {name: path} -> (by {arm: {id: repeat-0 row}}, reps {arm: {id: [rows]}})."""
    by, reps = {}, {}
    for name, path in specs.items():
        reps[name] = collections.defaultdict(list)
        for r in read_jsonl(path):
            reps[name][r["id"]].append(r)
        by[name] = {i: min(rs, key=lambda r: r.get("repeat", 0)) for i, rs in reps[name].items()}
    return by, reps


def join_labels(by, labels):
    """Labels keyed by every result id; a label file may use the 16-character id prefix. Exits when any result id has no label,
    because a silent drop would score a subset (e.g. only the held good pages) as if it were the whole set."""
    ids = set().union(*(set(v) for v in by.values()))
    out = {i: labels.get(i) or labels.get(i[:16]) for i in ids}
    missing = sum(v is None for v in out.values())
    if missing:
        sys.exit("LABEL JOIN: %d of %d result ids have no label" % (missing, len(ids)))
    return out


def labels_from_results(by):
    base = next(iter(by.values()))
    return {i: {"url_label": r["label"]} for i, r in base.items()}


def held(r):
    return r["decision"] == "hold"


def stopped(r):
    """The ad does not run: a hold, or a could-not-scan answer (callers that know only hold/pass treat anything but pass as a stop)."""
    return r["decision"] in ("hold", "could_not_scan")


def rate(k, n):
    lo, hi = wilson(k, n)
    return "%d/%d = %.1f%% wilson95 [%.1f, %.1f]" % (k, n, 100 * k / max(1, n), 100 * lo, 100 * hi)


def state(call):
    return {"PASS": "PASS", "HOLD": "HOLD"}.get(call["outcome"], "CANNOT")


# ---------------------------------------------------------------- the report
def analyse(by, reps, labels, strata, pairs, rule, out, tag="set", guard_points=1.0, named_kinds=()):
    """Prints the report through `out(line)`. -> {(X, Y): verdict string} of the selected rule."""
    ids = sorted(set.intersection(*(set(v) for v in by.values())) & set(labels))
    lab = lambda i: labels[i]["url_label"]      # noqa: E731
    grp = lambda i: labels[i].get("group")      # noqa: E731
    has_groups = any(grp(i) for i in ids)
    benign = [i for i in ids if lab(i) == "benign"]
    phish = [i for i in ids if lab(i) == "phish"]
    whole = [i for i in phish if grp(i) == "urlset"] if has_groups else phish
    visible = [i for i in phish if grp(i) == "visible" and labels[i].get("grade") in SURE]
    named = [i for i in visible if labels[i].get("kind") in named_kinds]
    out("%s PAGES benign=%d phish_url_label_group=%d visible_gold_silver=%d named_catch=%d lines %s" % (
        tag, len(benign), len(whole), len(visible), len(named), " ".join("%s=%d" % (a, len(by[a])) for a in by)))
    if has_groups:
        out("%s NOTE visible-group catch is sorted by the judge's model family and may be flattering; the URL-label group is the whole-service catch" % tag)

    for arm in by:
        out("%s CATCH %s %s" % (tag, arm, rate(sum(held(by[arm][i]) for i in whole), len(whole))))
        out("%s FALSE HOLD %s pooled %s" % (tag, arm, rate(sum(held(by[arm][i]) for i in benign), len(benign))))
        if visible:
            out("%s CATCH VISIBLE %s %s" % (tag, arm, rate(sum(held(by[arm][i]) for i in visible), len(visible))))
        for kind in sorted({labels[i]["kind"] for i in visible if labels[i].get("kind")}):
            sel = [i for i in visible if labels[i].get("kind") == kind]
            out("%s KIND CATCH %s %s %s" % (tag, arm, kind, rate(sum(held(by[arm][i]) for i in sel), len(sel))))
        kind_of = lambda i: (labels[i].get("kind") or "unsorted") if labels[i].get("grade", "none") != "none" else "unsorted"      # noqa: E731
        for kind in sorted({kind_of(i) for i in benign}):
            sel = [i for i in benign if kind_of(i) == kind]
            out("%s KIND FALSE HOLD %s %s %s" % (tag, arm, kind, rate(sum(held(by[arm][i]) for i in sel), len(sel))))
        for field in ("ptype",):
            for v in sorted({labels[i][field] for i in benign if labels[i].get(field)}):
                sel = [i for i in benign if labels[i].get(field) == v]
                out("%s FALSE HOLD %s %s=%s %s" % (tag, arm, field, v, rate(sum(held(by[arm][i]) for i in sel), len(sel))))
        for status in sorted(set(strata.get(i) for i in ids if i in strata)):
            for name, pool in (("FALSE HOLD", benign), ("CATCH", whole)):
                sel = [i for i in pool if strata.get(i) == status]
                if sel:
                    out("%s SITE %s %s %s %s" % (tag, name, arm, status, rate(sum(held(by[arm][i]) for i in sel), len(sel))))
        # range: a held page the sorters sure-grade as a scam is not counted in either bound; uncertain ones are counted for, then against
        hb = [i for i in benign if held(by[arm][i])]
        sure = sum(labels[i].get("grade") in SURE and labels[i].get("judge_expect") == "hold" for i in hb)
        unsure = sum((labels[i].get("grade") == "Bronze" and labels[i].get("judge_expect") == "hold") or (labels[i].get("grade", "none") != "none" and labels[i].get("judge_expect") == "either") for i in hb)
        out("%s FALSE HOLD RANGE %s headline=%d range=[%d, %d] of %d" % (tag, arm, len(hb), len(hb) - sure - unsure, len(hb) - sure, len(benign)))
        ns = [i for i in hb if labels[i].get("grade", "none") == "none"]
        out("%s NEEDS SORT %s held url_label=benign pages with no grade: %d" % (tag, arm, len(ns)))
        for i in ns:
            out("NEEDS_SORT_ID %s %s" % (arm, i))

    three = any(r["decision"] == "could_not_scan" for a in by for r in by[a].values())      # three outcomes only when some arm has could-not-scan
    first = next(iter(by))
    if three:
        for arm in by:
            out("%s GOOD STOPPED %s (hold or could_not_scan) %s" % (tag, arm, rate(sum(stopped(by[arm][i]) for i in benign), len(benign))))
            out("%s CATCH STOPPED %s (hold or could_not_scan) %s" % (tag, arm, rate(sum(stopped(by[arm][i]) for i in whole), len(whole))))
            cns = collections.Counter((grp(i) or ("good" if lab(i) == "benign" else "phish")) for i in ids if by[arm][i]["decision"] == "could_not_scan")
            out("%s COULD NOT SCAN %s total=%d %s" % (tag, arm, sum(cns.values()), " ".join("group=%s:%d" % kv for kv in sorted(cns.items()))))
            if arm != first:
                moved = sum(by[first][i]["decision"] == "pass" and by[arm][i]["decision"] == "could_not_scan" for i in benign)
                out("%s GOOD BASELINE-PASSED NOW COULD_NOT_SCAN %s vs %s: %d of %d" % (tag, arm, first, moved, sum(by[first][i]["decision"] == "pass" for i in benign)))

    for arm in by:      # stages (needs the per-call records of replay.py)
        for name, pool in (("benign", benign), ("phish", phish)):
            rows = [by[arm][i] for i in pool if by[arm][i].get("calls")]      # a could-not-scan answer has no model call
            if not rows:
                continue
            hs = collections.Counter(state(r["calls"][0]) for r in rows)
            sent = [r for r in rows if len(r["calls"]) > 1]
            ss = collections.Counter(state(r["calls"][1]) for r in sent)
            hold_pass = sum(state(r["calls"][0]) == "HOLD" and state(r["calls"][1]) == "PASS" for r in sent)
            pass_hold = sum(state(r["calls"][0]) == "PASS" and state(r["calls"][1]) == "HOLD" for r in sent)
            out("%s STAGE %s %s haiku_hold=%d haiku_pass=%d haiku_cannot=%d sent_to_sonnet=%d n=%d routed %s" % (
                tag, arm, name, hs["HOLD"], hs["PASS"], hs["CANNOT"], len(sent), len(rows),
                " ".join("%s=%d" % kv for kv in sorted(collections.Counter(r.get("routed_because") for r in sent).items(), key=str))))
            # decided = Haiku could not tell and Sonnet did: a resolution, not a confirmation
            decided = sum(state(r["calls"][0]) == "CANNOT" and state(r["calls"][1]) != "CANNOT" for r in sent)
            out("%s STAGE %s %s sonnet confirm=%d overturn=%d (hold_to_pass=%d pass_to_hold=%d) cannot_tell=%d decided_after_haiku_cannot=%d" % (
                tag, arm, name, len(sent) - ss["CANNOT"] - hold_pass - pass_hold - decided, hold_pass + pass_hold, hold_pass, pass_hold, ss["CANNOT"], decided))
        failed = sum(any(c.get("outcome") == "ERROR" for c in by[arm][i].get("calls", [])) for i in ids)
        out("%s API_FAILED %s pages_with_a_failed_call=%d" % (tag, arm, failed))
        for name, pool in (("benign", benign), ("phish", phish)):
            fx = collections.Counter()
            for i in pool:
                r = by[arm][i]
                if r.get("rule"):
                    fx[(r["rule"], "added" if held(r) and r["judge_decision"] != "hold" else "removed" if not held(r) and r["judge_decision"] == "hold" else "same")] += 1
            for rule_name in sorted({k[0] for k in fx}):
                out("%s RULE %s %s %s added_holds=%d removed_holds=%d" % (tag, arm, rule_name, name, fx[(rule_name, "added")], fx[(rule_name, "removed")]))

    def table(x, y, pool, f=held):
        a = b = c = d = 0
        for i in pool:
            hx, hy = f(by[x][i]), f(by[y][i])
            a, b, c, d = a + (hx and hy), b + (hx and not hy), c + (hy and not hx), d + (not hx and not hy)
        return a, b, c, d

    fh_t = {p: table(*p, benign) for p in pairs}
    ca_t = {p: table(*p, whole) for p in pairs}
    nm_t = {p: table(*p, named) for p in pairs}
    adj = lambda tabs: dict(zip(pairs, holm([mcnemar_exact(t[1], t[2]) for t in (tabs[p] for p in pairs)])))      # noqa: E731
    fh_adj, ca_adj, nm_adj = adj(fh_t), adj(ca_t), adj(nm_t)
    ci = lambda t: paired_interval(*t) if sum(t) else (0.0, 0.0, 0.0)      # noqa: E731
    if three:      # the same paired tests on "stopped": catch (the pass rule's measure) and good pages stopped
        for meas, pool in (("CATCH STOPPED", whole), ("GOOD STOPPED", benign)):
            tabs = {p: table(*p, pool, stopped) for p in pairs}
            for p, pa in zip(pairs, holm([mcnemar_exact(tabs[q][1], tabs[q][2]) for q in pairs])):
                t = tabs[p]
                if sum(t):
                    c = ci(t)
                    out("%s PAIRED %s vs %s %s both=%d only_%s=%d only_%s=%d neither=%d p_raw=%.4f p_holm=%.4f diff=%+.1f pts newcombe95=[%+.1f, %+.1f]" % (
                        tag, p[0], p[1], meas, t[0], p[0], t[1], p[1], t[2], t[3], mcnemar_exact(t[1], t[2]), pa, 100 * c[0], 100 * c[1], 100 * c[2]))
    cost = {a: sum(by[a][i]["cost"] for i in ids) for a in by}
    n = max(1, len(ids))
    for a in by:
        out("COST %s total=%.4f per_1000=%.2f ratio_to_%s=%.3f" % (a, cost[a], 1000 * cost[a] / n, first, cost[a] / cost[first] if cost[first] else float("nan")))
    res = {}
    for p in pairs:
        x, y = p
        name = "%s vs %s" % p
        for meas, t, pa in (("FALSE HOLD", fh_t[p], fh_adj[p]), ("CATCH", ca_t[p], ca_adj[p]), ("NAMED CATCH", nm_t[p], nm_adj[p])):
            if not sum(t):
                continue
            c = ci(t)
            out("%s PAIRED %s %s both=%d only_%s=%d only_%s=%d neither=%d p_raw=%.4f p_holm=%.4f diff=%+.1f pts newcombe95=[%+.1f, %+.1f]" % (
                tag, name, meas, t[0], x, t[1], y, t[2], t[3], mcnemar_exact(t[1], t[2]), pa, 100 * c[0], 100 * c[1], 100 * c[2]))
        fh, ca, nm = fh_t[p], ca_t[p], nm_t[p]
        fh_up, fh_down = fh_adj[p] < ALPHA and fh[1] > fh[2], fh_adj[p] < ALPHA and fh[1] < fh[2]
        ratio = cost[x] / cost[y] if cost[y] else float("inf")
        if rule == "a":
            guard_met = ci(ca)[1] > GUARD_A
            out("%s GUARD %s catch lower bound %+.1f pts %s (needs > -5.0)" % (tag, name, 100 * ci(ca)[1], "MET" if guard_met else "NOT MET"))
            res[p] = verdict_a(fh_up, fh_down, ca_adj[p] < ALPHA and ca[1] < ca[2], guard_met)
        elif rule == "b":
            catch_up, catch_down = nm_adj[p] < ALPHA and nm[1] > nm[2], nm_adj[p] < ALPHA and nm[1] < nm[2]
            upper = ci(fh)[2]
            guard_met = upper <= guard_points / 100
            out("%s GUARD %s false-hold increase upper bound %+.1f pts %s (needs <= %.1f)" % (tag, name, 100 * upper, "MET" if guard_met else "NOT MET", guard_points))
            res[p] = verdict_b(fh_up, catch_up, catch_down, guard_met)
        else:
            carry, failing = verdict_c(nm_adj[p] < ALPHA and nm[1] > nm[2], sum(held(by[x][i]) for i in benign) <= sum(held(by[y][i]) for i in benign), ratio <= COST_LIMIT)
            out("%s COST RATIO %s %.3f" % (tag, name, ratio))
            res[p] = "carry to holdout" if carry else "stop: " + "; ".join(failing)
        out("VERDICT %s: %s" % (name, res[p]))

    flips = {a: [rs for rs in reps[a].values() if len(rs) > 1] for a in by}
    for a, rss in flips.items():
        if rss:
            out("%s FLIPS %s pages_with_repeats=%d decision_differs_between_repeats=%d" % (tag, a, len(rss), sum(len({r["decision"] for r in rs}) > 1 for rs in rss)))
    return res


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--results", action="append", required=True, help="NAME=path; the first is the baseline")
    ap.add_argument("--labels")
    ap.add_argument("--strata")
    ap.add_argument("--pairs", help="X:Y,X:Y (default: each other arm vs the first)")
    ap.add_argument("--rule", choices=("a", "b", "c"), default="a")
    ap.add_argument("--guard-points", type=float, default=1.0)
    ap.add_argument("--named-kinds", default="")
    ap.add_argument("--tag", default="set")
    ap.add_argument("--out")
    a = ap.parse_args()
    if a.rule == "c" and not a.named_kinds:
        ap.error("--rule c needs --named-kinds (the carry rule's main measure)")
    by, reps = load_arms(dict(s.split("=", 1) for s in a.results))
    labels = join_labels(by, {r["id"]: r for r in read_jsonl(a.labels)}) if a.labels else labels_from_results(by)
    strata = {r["id"]: r["status"] for r in read_jsonl(a.strata)} if a.strata else {}
    arms = list(by)
    pairs = [tuple(p.split(":")) for p in a.pairs.split(",")] if a.pairs else [(x, arms[0]) for x in arms[1:]]
    lines = []

    def out(s):
        lines.append(s)
        print(s)
    analyse(by, reps, labels, strata, pairs, a.rule, out, a.tag, a.guard_points, tuple(k for k in a.named_kinds.split(",") if k))
    if a.out:
        with open(a.out, "w", encoding="utf-8") as f:
            f.write("\n".join(lines) + "\n")


if __name__ == "__main__":
    main()
