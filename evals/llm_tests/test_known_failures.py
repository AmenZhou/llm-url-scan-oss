"""One case per page of cases.jsonl + guards.jsonl: the service's own judge path (Haiku, Sonnet by its routing, its decision) must give the
expected outcome (hold | pass | could_not_scan) on 2 of 2 runs. Only pages with a clear expected outcome belong in the case files:
add a case by appending a line to cases.jsonl."""
import json
import os

import pytest

from evals import replay as R
from evals.llm_tests import conftest as C

pytestmark = pytest.mark.eval


def load_cases():
    rows = []
    for name in ("cases.jsonl", "guards.jsonl"):
        p = os.path.join(C.CASES_DIR, name)
        if os.path.isfile(p):
            with open(p, encoding="utf-8") as f:
                rows += [json.loads(x) for x in f if x.strip()]
    return rows


CASES = load_cases()
PARAMS = [pytest.param(c, id="%s-%s" % (c["group"].replace(":", "-"), c["id"][:16])) for c in CASES] or [pytest.param(None, id="no-cases")]


@pytest.mark.parametrize("case", PARAMS)
def test_expected_outcome_on_both_runs(case, ctx):
    if case is None:
        pytest.skip("no case file")
    with open(case["page_path"], encoding="utf-8") as f:
        rec = json.load(f)
    rec["id"] = case["id"]
    lines = []
    for repeat in range(C.REPEATS):
        try:
            lines.append(R.judge_page(rec, ctx["arm"], ctx["client"], ctx["ledger"], C.RUN, C.RUN_CAP, C.GRAND_CAP, repeat, ctx["state"]))
        except R.Refused as e:
            pytest.fail("ledger refused (%s cap): id=%s repeat=%d" % (e.args[0], case["id"], repeat))
        except R.Halt as e:
            pytest.fail("model calls halted (%s): id=%s" % (e.args[0], case["id"]))
    got = [x["decision"] for x in lines]
    ok = got == [case["expected"]] * C.REPEATS
    C.RESULTS.append({"id": case["id"], "group": case["group"], "expected": case["expected"], "got": got, "reasons": [x["reason"] for x in lines], "ok": ok,
                      "spent_run": ctx["ledger"].spent(C.RUN), "spent_total": ctx["ledger"].spent()})
    if C.OUT:
        with open(C.OUT, "a", encoding="utf-8") as f:
            f.write(json.dumps({"id": case["id"], "group": case["group"], "expected": case["expected"], "decisions": got, "reasons": C.RESULTS[-1]["reasons"],
                                "cost": round(sum(x["cost"] for x in lines), 6)}, sort_keys=True) + "\n")
    assert ok, "id=%s group=%s expected=%s got=%s reasons=%s" % (case["id"], case["group"], case["expected"], got, C.RESULTS[-1]["reasons"])
