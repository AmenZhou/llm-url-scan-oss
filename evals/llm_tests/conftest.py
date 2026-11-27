"""Real-model eval suite: settings and the shared client/ledger. Run by path: `pytest -m eval evals/llm_tests` (the default run deselects `eval`).

Environment (all optional)
  LLMURL_EVAL_CASES_DIR   folder with cases.jsonl and guards.jsonl (id, source, page_path, group, expected); outside git
  LLMURL_EVAL_TARGET      worktree whose `llm_url_scan` is judged: the changed build (default: this one) or the unchanged one (the baseline worktree)
  LLMURL_EVAL_KEY_FILE    key file; LLMURL_EVAL_LEDGER the shared ledger; LLMURL_EVAL_RUN_CAP (USD, default 1.50) and LLMURL_EVAL_GRAND_CAP the caps
  LLMURL_EVAL_OUT         optional jsonl: one line per case (ids, expected, decisions, reasons, cost; no page text)
  LLMURL_EVAL_PROMPT      optional path to a prompt file the arm uses instead of the service's pinned prompt (judge.load_prompt());
                          test only, e.g. LLMURL_EVAL_PROMPT=llm_url_scan/prompts/prompt-v3.md. The service itself always loads prompt-v5.
  LLMURL_SHOP_ROUTING     1 = the arm also routes price-and-cart pages to Sonnet; anything else = what the service ships (off)
  LLMURL_EVAL_ANYPRICE    1 = the arm routes every page showing a price amount to Sonnet (harness only, a superset of shop routing); else off
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

CASES_DIR = os.environ.get("LLMURL_EVAL_CASES_DIR", "")
KEY_FILE = os.environ.get("LLMURL_EVAL_KEY_FILE", R.KEY_FILE)
LEDGER = os.environ.get("LLMURL_EVAL_LEDGER", "")      # required: one shared ledger keeps the grand cap true across runs
RUN_CAP = float(os.environ.get("LLMURL_EVAL_RUN_CAP", "1.50"))
GRAND_CAP = float(os.environ.get("LLMURL_EVAL_GRAND_CAP", "16.32"))
OUT = os.environ.get("LLMURL_EVAL_OUT")
PROMPT_FILE = os.environ.get("LLMURL_EVAL_PROMPT")
SHOP_ROUTING = os.environ.get("LLMURL_SHOP_ROUTING") == "1"      # same switch and default as the service
ANYPRICE = os.environ.get("LLMURL_EVAL_ANYPRICE") == "1"      # harness-only switch, not in the service
RUN = "eval-" + time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
REPEATS = 2
RESULTS = []      # one dict per finished case, for the summary


def skip_reason():
    """Why the suite cannot run, or None."""
    if TARGET and not os.path.isdir(TARGET):
        return "LLMURL_EVAL_TARGET is not a folder"
    if PROMPT_FILE and not os.path.isfile(PROMPT_FILE):
        return "LLMURL_EVAL_PROMPT is not a file"
    if not CASES_DIR or not os.path.isfile(os.path.join(CASES_DIR, "cases.jsonl")):
        return "case file cases.jsonl not found in LLMURL_EVAL_CASES_DIR"
    if not LEDGER:
        return "LLMURL_EVAL_LEDGER not set"
    if not os.path.isfile(KEY_FILE):
        return "API key file not found (LLMURL_EVAL_KEY_FILE)"
    return None


def eval_arm(prompt):
    return R.Arm("EVAL", prompt, shop=SHOP_ROUTING, anyprice=ANYPRICE)


def eval_prompt(judge):
    """The arm's system prompt: LLMURL_EVAL_PROMPT's file when set, else the service's pinned prompt."""
    if PROMPT_FILE:
        with open(PROMPT_FILE, encoding="utf-8") as f:
            return f.read()
    return judge.load_prompt()


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
    return {"arm": eval_arm(eval_prompt(judge)), "client": judge.build_client(keys.read_env_value(KEY_FILE, R.KEY_VAR)),
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
