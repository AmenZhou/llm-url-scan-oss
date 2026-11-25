"""Real-model eval suite: settings and the shared client/ledger. Run by path: `pytest -m eval evals/llm_tests` (the default run deselects `eval`).

Environment (all optional)
  LLMURL_EVAL_CASES_DIR   folder with cases.jsonl and guards.jsonl (id, source, page_path, group, expected); outside git
  LLMURL_EVAL_TARGET      worktree whose `llm_url_scan` is judged: the changed build (default: this one) or the unchanged one (the baseline worktree)
  LLMURL_EVAL_KEY_FILE    key file; LLMURL_EVAL_LEDGER the shared ledger; LLMURL_EVAL_RUN_CAP (USD, default 1.50) and LLMURL_EVAL_GRAND_CAP the caps
  LLMURL_EVAL_OUT         optional jsonl: one line per case (ids, expected, decisions, reasons, cost; no page text)
Prints counts and ids only. Existence of the key file is checked here; it is read only when the first case runs.
"""
import collections
import os
import sys
import time

import pytest

TARGET = os.environ.get("LLMURL_EVAL_TARGET")
if TARGET and os.path.isdir(TARGET):
    sys.path.insert(0, TARGET)      # before anything imports llm_url_scan: the build under test

from evals import replay as R  # noqa: E402

CASES_DIR = os.environ.get("LLMURL_EVAL_CASES_DIR", "/Users/haimengzhou/apps/ai-console/tmp/known-failures/eval-cases/")
KEY_FILE = os.environ.get("LLMURL_EVAL_KEY_FILE", R.KEY_FILE)
LEDGER = os.environ.get("LLMURL_EVAL_LEDGER", "/Users/haimengzhou/apps/ai-console/tmp/evals/ledger.jsonl")
RUN_CAP = float(os.environ.get("LLMURL_EVAL_RUN_CAP", "1.50"))
GRAND_CAP = float(os.environ.get("LLMURL_EVAL_GRAND_CAP", "16.32"))
OUT = os.environ.get("LLMURL_EVAL_OUT")
RUN = "eval-" + time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
REPEATS = 2
RESULTS = []      # one dict per finished case, for the summary


def skip_reason():
    """Why the suite cannot run, or None."""
    if TARGET and not os.path.isdir(TARGET):
        return "LLMURL_EVAL_TARGET is not a folder"
    if not os.path.isfile(os.path.join(CASES_DIR, "cases.jsonl")):
        return "case file cases.jsonl not found in LLMURL_EVAL_CASES_DIR"
    if not os.path.isfile(KEY_FILE):
        return "API key file not found (LLMURL_EVAL_KEY_FILE)"
    return None


@pytest.fixture(scope="session")
def ctx():
    why = skip_reason()
    if why:
        pytest.skip(why)
    bad = sorted(k for k in os.environ if k.upper().startswith("ANTHROPIC_") or any(w in k.upper() for w in ("_LOG", "CUSTOM_HEADERS", "PROXY", "KEYLOG")))
    if bad:
        pytest.fail("BAD ENV (%d variable names)" % len(bad))
    from llm_url_scan import judge, keys
    if TARGET:      # the build under test must be the one that loaded
        assert os.path.realpath(judge.__file__).startswith(os.path.realpath(TARGET)), "llm_url_scan was not loaded from LLMURL_EVAL_TARGET"
    return {"arm": R.Arm("EVAL", judge.load_prompt()), "client": judge.build_client(keys.read_env_value(KEY_FILE, R.KEY_VAR)),
            "ledger": R.Ledger(LEDGER), "state": {"err_run": 0}}


def pytest_terminal_summary(terminalreporter):
    if not RESULTS:
        return
    w = terminalreporter.write_line
    by = collections.defaultdict(lambda: [0, 0])
    for r in RESULTS:
        by[r["group"]][0 if r["ok"] else 1] += 1
    w("EVAL SUMMARY build=%s run=%s cases=%d expected_on_2_of_2=%d failed=%d" % (
        "target" if TARGET else "this-worktree", RUN, len(RESULTS), sum(r["ok"] for r in RESULTS), sum(not r["ok"] for r in RESULTS)))
    for g, (ok, bad) in sorted(by.items()):
        w("EVAL GROUP %s ok=%d failed=%d" % (g, ok, bad))
    for r in RESULTS:
        if not r["ok"]:
            w("EVAL FAILED id=%s group=%s expected=%s got=%s reasons=%s" % (r["id"], r["group"], r["expected"], ",".join(r["got"]), ",".join(r["reasons"])))
    w("EVAL SPENT run=%.4f total=%.4f (run cap %.2f)" % (RESULTS[-1]["spent_run"], RESULTS[-1]["spent_total"], RUN_CAP))
