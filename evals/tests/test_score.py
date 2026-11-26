import os
import re

import pytest

from evals import score as SC

PREREG_DIR = os.environ.get("LLMURL_EVAL_PREREG_DIR", "")      # saved results of an earlier run, outside git; test skips without them
NAMED = ("fake_shop",)


# ---------------------------------------------------------------- decision rules, each branch
def test_rule_a_five_verdicts():
    v = SC.verdict_a
    assert v(True, False, False, True) == "shown worse"
    assert v(True, False, True, True) == "shown worse"
    assert v(False, True, True, False) == "trade-off"
    assert v(False, False, True, False) == "shown worse"
    assert v(False, True, False, True) == "shown better"
    assert v(False, True, False, False) == "better on holds, catch not assured"
    assert v(False, False, False, True) == "not shown different"


def test_rule_b_verdicts():
    v = SC.verdict_b       # (fh_up, catch_up, catch_down, guard_met)
    assert v(True, True, False, True) == "shown worse"
    assert v(False, False, True, True) == "shown worse"
    assert v(False, True, False, True) == "shown better"
    assert v(False, True, False, False) == "better on catch, holds not assured"
    assert v(False, False, False, True) == "not shown different"


def test_rule_c_carry():
    assert SC.verdict_c(True, True, True) == (True, [])
    assert SC.verdict_c(False, True, True)[1] == ["named catch not shown up"]
    assert SC.verdict_c(True, False, True)[1] == ["false-hold count higher than baseline"]
    assert SC.verdict_c(True, True, False)[1] == ["cost ratio above 1.25"]
    assert len(SC.verdict_c(False, False, False)[1]) == 3


# ---------------------------------------------------------------- end to end on synthetic sets
def row(i, label, decision, cost=1.0):
    return {"id": i, "label": label, "decision": decision, "cost": cost, "repeat": 0}


def build(n_benign, base_fh, cand_fh, named_n, base_named, cand_named, cand_cost=1.0, cand_cost_extra=0.0):
    """Baseline BASE and candidate CAND: benign pages b0.., visible fake-shop pages s0.., a whole-service group u0..u99 (held by both)."""
    labels, base, cand = {}, {}, {}
    for k in range(n_benign):
        i = "b%d" % k
        labels[i] = {"id": i, "url_label": "benign", "group": "good", "grade": "none"}
        base[i], cand[i] = row(i, "benign", "hold" if k < base_fh else "pass"), row(i, "benign", "hold" if k < cand_fh else "pass", cand_cost)
    for k in range(named_n):
        i = "s%d" % k
        labels[i] = {"id": i, "url_label": "phish", "group": "visible", "grade": "Gold", "kind": "fake_shop"}
        base[i], cand[i] = row(i, "phish", "hold" if k < base_named else "pass"), row(i, "phish", "hold" if k < cand_named else "pass", cand_cost)
    for k in range(100):
        i = "u%d" % k
        labels[i] = {"id": i, "url_label": "phish", "group": "urlset", "grade": "none"}
        base[i], cand[i] = row(i, "phish", "hold"), row(i, "phish", "hold", cand_cost)
    by = {"BASE": base, "CAND": cand}
    return by, {a: {i: [r] for i, r in v.items()} for a, v in by.items()}, labels


def verdict(rule, **kw):
    by, reps, labels = build(**kw)
    return SC.analyse(by, reps, labels, {}, [("CAND", "BASE")], rule, lambda s: None, guard_points=1.0, named_kinds=NAMED)[("CAND", "BASE")]


def test_rule_b_end_to_end_each_verdict():
    up = dict(named_n=40, base_named=0, cand_named=12, base_fh=0, cand_fh=0)
    assert verdict("b", n_benign=1000, **up) == "shown better"                  # 0 of 1000 held both: upper bound 0.4 pts <= 1
    assert verdict("b", n_benign=100, **up) == "better on catch, holds not assured"      # upper bound 3.7 pts > 1
    assert verdict("b", n_benign=100, named_n=40, base_named=0, cand_named=12, base_fh=0, cand_fh=15) == "shown worse"      # false holds shown up
    assert verdict("b", n_benign=100, named_n=40, base_named=12, cand_named=0, base_fh=0, cand_fh=0) == "shown worse"      # catch shown down
    assert verdict("b", n_benign=100, named_n=40, base_named=3, cand_named=5, base_fh=0, cand_fh=0) == "not shown different"


def test_rule_c_end_to_end():
    ok = dict(n_benign=100, named_n=40, base_named=0, cand_named=12, base_fh=3, cand_fh=3)
    assert verdict("c", **ok) == "carry to holdout"
    assert verdict("c", cand_cost=1.3, **ok) == "stop: cost ratio above 1.25"
    assert verdict("c", **dict(ok, cand_fh=4)) == "stop: false-hold count higher than baseline"
    assert verdict("c", **dict(ok, cand_named=1)).startswith("stop: named catch not shown up")


def test_rule_a_end_to_end_lower_holds():
    kw = dict(n_benign=300, named_n=0, base_named=0, cand_named=0, cand_fh=0)
    by, reps, labels = build(base_fh=60, **kw)
    res = SC.analyse(by, reps, labels, {}, [("CAND", "BASE")], "a", lambda s: None)
    assert res[("CAND", "BASE")] == "shown better"


def test_report_lines_counts_only_ranges_strata_and_needs_sort():
    by, reps, labels = build(n_benign=20, base_fh=2, cand_fh=4, named_n=10, base_named=2, cand_named=6)
    labels["b0"].update(grade="Gold", kind="fake_shop", judge_expect="hold")      # sure scam held by both arms: out of both bounds
    labels["b3"].update(grade="Bronze", kind="ordinary", judge_expect="either")      # CAND holds it: uncertain
    by["CAND"]["b1"]["calls"] = [{"outcome": "HOLD"}, {"outcome": "PASS"}]
    by["CAND"]["b1"]["routed_because"] = "h_hold"
    lines = []
    SC.analyse(by, reps, labels, {"b0": "phish_only", "b1": "unknown"}, [("CAND", "BASE")], "b", lines.append, named_kinds=NAMED)
    text = "\n".join(lines)
    assert "set FALSE HOLD RANGE CAND headline=4 range=[2, 3] of 20" in text
    assert "set NEEDS SORT CAND held url_label=benign pages with no grade: 2" in text and "NEEDS_SORT_ID CAND b1" in text and "NEEDS_SORT_ID CAND b0" not in text
    assert "set KIND CATCH CAND fake_shop 6/10" in text and "set SITE FALSE HOLD CAND phish_only 1/1" in text
    assert "set STAGE CAND benign sonnet confirm=0 overturn=1 (hold_to_pass=1 pass_to_hold=0) cannot_tell=0" in text
    assert "http" not in text


def test_api_failures_counted_and_cannot_tell_resolutions_not_called_confirms():
    by, reps, labels = build(n_benign=4, base_fh=0, cand_fh=0, named_n=0, base_named=0, cand_named=0)
    by["CAND"]["b0"]["calls"] = [{"outcome": "CANNOT_TELL"}, {"outcome": "PASS"}]      # Haiku could not tell, Sonnet decided
    by["CAND"]["b1"]["calls"] = [{"outcome": "PASS"}, {"outcome": "PASS"}]             # a real confirmation
    by["CAND"]["b2"]["calls"] = [{"outcome": "ERROR"}, {"outcome": "ERROR"}]           # both calls failed
    lines = []
    SC.analyse(by, reps, labels, {}, [("CAND", "BASE")], "a", lines.append)
    assert "set STAGE CAND benign sonnet confirm=1 overturn=0 (hold_to_pass=0 pass_to_hold=0) cannot_tell=1 decided_after_haiku_cannot=1" in lines
    assert "set API_FAILED CAND pages_with_a_failed_call=1" in lines and "set API_FAILED BASE pages_with_a_failed_call=0" in lines


def test_label_join_accepts_short_ids_and_refuses_missing_labels():
    full = "a" * 64
    by = {"BASE": {full: row(full, "benign", "pass"), "x" * 64: row("x" * 64, "benign", "pass")}}
    with pytest.raises(SystemExit, match="1 of 2 result ids have no label"):
        SC.join_labels(by, {full[:16]: {"url_label": "benign"}})
    del by["BASE"]["x" * 64]
    assert SC.join_labels(by, {full[:16]: {"url_label": "benign"}}) == {full: {"url_label": "benign"}}


def test_rule_c_without_named_kinds_is_refused(tmp_path, monkeypatch, capsys):
    p = tmp_path / "r.jsonl"
    p.write_text('{"id": "b0", "label": "benign", "decision": "pass", "cost": 1.0}\n')
    monkeypatch.setattr("sys.argv", ["score", "--results", "BASE=%s" % p, "--results", "CAND=%s" % p, "--rule", "c"])
    with pytest.raises(SystemExit):
        SC.main()
    assert "--rule c needs --named-kinds" in capsys.readouterr().err


def test_flips_between_repeats():
    by, reps, labels = build(n_benign=4, base_fh=0, cand_fh=0, named_n=0, base_named=0, cand_named=0)
    reps["BASE"]["b0"].append(dict(row("b0", "benign", "hold"), repeat=1))
    lines = []
    SC.analyse(by, reps, labels, {}, [("CAND", "BASE")], "a", lines.append)
    assert "set FLIPS BASE pages_with_repeats=1 decision_differs_between_repeats=1" in lines


def test_rule_effects_from_rules_replay_rows():
    by, reps, labels = build(n_benign=4, base_fh=0, cand_fh=0, named_n=0, base_named=0, cand_named=0)
    by["CAND"]["b0"].update(decision="hold", judge_decision="pass", rule="known_site")
    lines = []
    SC.analyse(by, reps, labels, {}, [("CAND", "BASE")], "a", lines.append)
    assert "set RULE CAND known_site benign added_holds=1 removed_holds=0" in lines


def test_three_outcomes_stopped_vs_hold_only_and_could_not_scan_counts():
    by, reps, labels = build(n_benign=10, base_fh=1, cand_fh=2, named_n=0, base_named=0, cand_named=0)      # BASE holds b0; CAND holds b0, b1
    for i in ("b2", "b3", "b4"):      # CAND answers could-not-scan on three pages BASE passed
        by["CAND"][i]["decision"] = "could_not_scan"
    for k in range(30):      # 30 whole-service phishing pages BASE passes, CAND stops: 10 as hold, 20 as could-not-scan
        by["BASE"]["u%d" % k]["decision"] = "pass"
        by["CAND"]["u%d" % k]["decision"] = "hold" if k < 10 else "could_not_scan"
    lines = []
    SC.analyse(by, reps, labels, {}, [("CAND", "BASE")], "a", lines.append)
    text = "\n".join(lines)
    assert "set FALSE HOLD CAND pooled 2/10" in text and "set GOOD STOPPED CAND (hold or could_not_scan) 5/10" in text      # hold only / stopped
    assert "set CATCH CAND 80/100" in text and "set CATCH STOPPED CAND (hold or could_not_scan) 100/100" in text
    assert "set COULD NOT SCAN CAND total=23 group=good:3 group=urlset:20" in text and "set COULD NOT SCAN BASE total=0" in text
    assert "set GOOD BASELINE-PASSED NOW COULD_NOT_SCAN CAND vs BASE: 3 of 9" in text
    mc = [x for x in lines if "PAIRED CAND vs BASE CATCH STOPPED" in x][0]
    assert "only_CAND=30 only_BASE=0" in mc and "p_holm=0.0000" in mc      # McNemar on "stopped"
    assert [x for x in lines if "PAIRED CAND vs BASE CATCH both" in x][0].count("only_CAND=10") == 1      # the hold-only test is unchanged


def test_two_outcome_results_print_no_three_outcome_lines():
    by, reps, labels = build(n_benign=4, base_fh=0, cand_fh=1, named_n=0, base_named=0, cand_named=0)
    lines = []
    SC.analyse(by, reps, labels, {}, [("CAND", "BASE")], "a", lines.append)
    assert not [x for x in lines if "STOPPED" in x or "COULD NOT SCAN" in x]


def test_could_not_scan_rows_without_model_calls_do_not_break_the_stage_lines():
    by, reps, labels = build(n_benign=3, base_fh=0, cand_fh=0, named_n=0, base_named=0, cand_named=0)
    by["CAND"]["b0"].update(decision="could_not_scan", calls=[])
    by["CAND"]["b1"]["calls"] = [{"outcome": "PASS"}]
    lines = []
    SC.analyse(by, reps, labels, {}, [("CAND", "BASE")], "a", lines.append)
    assert "set STAGE CAND benign haiku_hold=0 haiku_pass=1 haiku_cannot=0 sent_to_sonnet=0 n=1 routed " in lines


# ---------------------------------------------------------------- recompute of the November L summary from the saved results
@pytest.mark.skipif(not os.path.exists(PREREG_DIR + "/L-RAG.jsonl"), reason="saved L results not present")
def test_recompute_reproduces_L_summary():
    by, reps = SC.load_arms({a: "%s/L-%s.jsonl" % (PREREG_DIR, a) for a in ("BASE", "FEW", "RAG")})
    labels = SC.labels_from_results(by)
    lines = []
    pairs = [("FEW", "BASE"), ("RAG", "BASE"), ("RAG", "FEW")]
    res = SC.analyse(by, reps, labels, {}, pairs, "a", lines.append, tag="L")
    with open(PREREG_DIR + "/L-summary.txt", encoding="utf-8") as f:
        summary = set(f.read().splitlines())
    mine = [x for x in lines if re.match(r"L (CATCH \w+ \d|FALSE HOLD \w+ pooled|PAIRED|GUARD)|VERDICT|COST (BASE|FEW|RAG)", x)]
    assert len(mine) == 3 + 3 + 6 + 3 + 3 + 3          # catch, false hold, paired x2 per pair, guard, verdict, cost
    assert not [x for x in mine if x not in summary]
    assert [sum(r["decision"] == "hold" for i, r in by[a].items() if r["label"] == "phish") for a in ("BASE", "FEW", "RAG")] == [103, 102, 101]
    assert [sum(r["decision"] == "hold" for i, r in by[a].items() if r["label"] == "benign") for a in ("BASE", "FEW", "RAG")] == [6, 6, 7]
    assert set(res.values()) == {"not shown different"}
