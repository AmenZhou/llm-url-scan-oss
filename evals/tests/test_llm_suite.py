"""The eval suite's own logic on a fake model: no network, no ledger file outside tmp_path."""
import json

import pytest

from evals import replay as R
from evals.llm_tests import conftest as C
from evals.llm_tests import test_known_failures as K
from evals.tests.test_replay import PROMPT, SHOP, Fake, answer


@pytest.fixture
def ctx(tmp_path, monkeypatch):
    monkeypatch.setattr(C, "RESULTS", [])
    monkeypatch.setattr(C, "OUT", str(tmp_path / "out.jsonl"))
    reply = lambda m, c: answer("benign") if "haiku" in m else answer("phishing", ["R5"])      # noqa: E731
    return {"arm": R.Arm("EVAL", PROMPT), "client": Fake(reply), "ledger": R.Ledger(str(tmp_path / "ledger.jsonl")), "state": {"err_run": 0}}


def case(tmp_path, expected):
    p = tmp_path / "page.json"
    p.write_text(json.dumps({"url": "https://example.test/s", "html": SHOP, "label": "phish"}))
    return {"id": "c" * 64, "source": "T", "page_path": str(p), "group": "miss:K3", "expected": expected}


def test_case_passes_when_both_runs_give_the_expected_outcome_and_writes_ids_only(ctx, tmp_path):
    K.test_expected_outcome_on_both_runs(case(tmp_path, "hold"), ctx)      # shop routing sends the Haiku pass to Sonnet, which holds
    assert C.RESULTS[0]["ok"] and C.RESULTS[0]["got"] == ["hold", "hold"]
    line = json.loads((tmp_path / "out.jsonl").read_text())
    assert line["decisions"] == ["hold", "hold"] and "example.test" not in json.dumps(line) and line["cost"] > 0


def test_case_fails_on_a_different_outcome(ctx, tmp_path):
    with pytest.raises(AssertionError, match="expected=pass"):
        K.test_expected_outcome_on_both_runs(case(tmp_path, "pass"), ctx)


def test_case_fails_when_the_ledger_run_cap_refuses(ctx, tmp_path, monkeypatch):
    monkeypatch.setattr(C, "RUN_CAP", 0.0)
    with pytest.raises(pytest.fail.Exception, match="ledger refused"):
        K.test_expected_outcome_on_both_runs(case(tmp_path, "hold"), ctx)
    assert ctx["client"].calls == []      # refused before any call
