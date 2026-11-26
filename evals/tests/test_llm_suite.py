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
    return {"arm": R.Arm("EVAL", PROMPT, shop=True), "client": Fake(reply), "ledger": R.Ledger(str(tmp_path / "ledger.jsonl")), "state": {"err_run": 0}}


def case(tmp_path, expected):
    p = tmp_path / "page.json"
    p.write_text(json.dumps({"url": "https://example.test/s", "html": SHOP, "label": "phish"}))
    return {"id": "c" * 64, "source": "T", "page_path": str(p), "group": "miss:K3", "expected": expected}


def test_case_passes_when_both_runs_give_the_expected_outcome_and_writes_ids_only(ctx, tmp_path):
    K.test_expected_outcome_on_both_runs(case(tmp_path, "hold"), ctx)      # shop routing sends the Haiku pass to Sonnet, which holds
    assert C.RESULTS[0]["ok"] and C.RESULTS[0]["got"] == ["hold", "hold"]
    line = json.loads((tmp_path / "out.jsonl").read_text())
    assert line["decisions"] == ["hold", "hold"] and "example.test" not in json.dumps(line) and line["cost"] > 0


def test_shop_routing_is_off_by_default_in_the_suite(ctx, tmp_path):
    assert C.SHOP_ROUTING is False      # LLMURL_SHOP_ROUTING=1 turns it on
    ctx["arm"] = R.Arm("EVAL", PROMPT, shop=C.SHOP_ROUTING)
    K.test_expected_outcome_on_both_runs(case(tmp_path, "pass"), ctx)


def test_case_fails_on_a_different_outcome(ctx, tmp_path):
    with pytest.raises(AssertionError, match="expected=pass"):
        K.test_expected_outcome_on_both_runs(case(tmp_path, "pass"), ctx)


def test_case_fails_when_the_ledger_run_cap_refuses(ctx, tmp_path, monkeypatch):
    monkeypatch.setattr(C, "RUN_CAP", 0.0)
    with pytest.raises(pytest.fail.Exception, match="ledger refused"):
        K.test_expected_outcome_on_both_runs(case(tmp_path, "hold"), ctx)
    assert ctx["client"].calls == []      # refused before any call


def test_eval_prompt_reads_the_file_named_by_the_env_var_else_the_pinned_prompt(monkeypatch):
    from llm_url_scan import judge
    monkeypatch.setattr(C, "PROMPT_FILE", None)
    assert C.eval_prompt(judge) == judge.load_prompt()
    v5 = judge.PROMPT_PATH.with_name("prompt-v5.md")
    monkeypatch.setattr(C, "PROMPT_FILE", str(v5))
    assert C.eval_prompt(judge) == v5.read_text(encoding="utf-8") != judge.load_prompt()


def test_prompt_v5_keeps_v3_rule_codes_and_answer_format_so_the_parser_accepts_it():
    from llm_url_scan import judge
    v3 = judge.load_prompt().splitlines()
    v5 = judge.PROMPT_PATH.with_name("prompt-v5.md").read_text(encoding="utf-8").splitlines()
    changed = [i for i, (a, b) in enumerate(zip(v3, v5)) if a != b]
    assert len(v3) == len(v5) and len(changed) == 1 and v5[changed[0]].startswith(v3[changed[0]])      # one clause appended to one rule
    assert [l[:3] for l in v5 if l[:1] == "R" and l[1:2].isdigit()] == ["R%d " % i for i in range(1, 10)]
    sample = 'x {"verdict": "suspicious", "rules": ["R2"], "brand": "B", "quotes": ["q"], "injection_text": false} y'
    assert judge.parse_answer(sample) == {"verdict": "suspicious", "rules": ["R2"], "brand": "B", "quotes": ["q"], "injection_text": False}
