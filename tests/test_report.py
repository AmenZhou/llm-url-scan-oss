"""Weekly counts report on a made-up 50-scan log written through the real (guarded) log writer. No address anywhere."""
from datetime import datetime, timezone

import pytest

from llm_url_scan import cli, report
from llm_url_scan.logs import LogWriter

T = datetime(2026, 11, 3, 12, 0, 0, tzinfo=timezone.utc)
YEAR, WEEK = T.isocalendar()[0], T.isocalendar()[1]


def hid(i):
    return "%064x" % (i + 1)


def write_log(d):
    log = LogWriter(d, clock=lambda: T)
    base = dict(salt_ver=1, caller="owner", capture_ms=30000, latency_ms=33000, wr_d0_date="2026-11-03")
    i = 0
    for _ in range(30):            # Haiku pass
        log.write("scan", hid=hid(i), decision="pass", reason="pass_haiku", readable=True, d1a_state="PASS", h_state="PASS", h_reason="verdict",
                  h_latency_s=2.8, wr_d0="negative", cost_usd=0.0006, text_chars=3000, p15="longer", **base)
        i += 1
    for k in range(10):            # Haiku hold, Sonnet hold
        log.write("scan", hid=hid(i), decision="hold", reason="hold_sonnet_verdict", readable=True, d1a_state="HOLD", h_state="HOLD", s_state="HOLD",
                  s_routed_because="h_hold", h_latency_s=2.8, s_latency_s=1.7, wr_d0="positive" if k < 4 else "negative", cost_usd=0.008,
                  p05=1 if k < 3 else 0, p15="thin", **base)
        i += 1
    for k in range(5):             # Haiku hold overridden by a Sonnet pass
        log.write("scan", hid=hid(i), decision="pass", reason="pass_sonnet_overrode_hold", readable=True, d1a_state="PASS", h_state="HOLD",
                  s_state="PASS", s_routed_because="h_hold", s_injection=k == 0, truncated=k == 0, wr_d0="negative", cost_usd=0.008, **base)
        i += 1
    for k in range(5):             # unreadable, held
        log.write("scan", hid=hid(i), decision="hold", reason="unreadable_gone" if k < 3 else "unreadable_proxy_refused", readable=False,
                  unreadable_reason="gone" if k < 3 else "proxy_refused", range_class=None if k < 3 else "private", d1a_state="UNREAD",
                  wr_d0="not_checked", cost_usd=0, **base)
        i += 1
    for j in (0, 1):
        log.write("recheck", hid=hid(j), salt_ver=1, wr_d7="positive", age_days=7, wr_attempts=1)       # two Haiku passes listed later
    for j in range(30, 36):
        log.write("recheck", hid=hid(j), salt_ver=1, wr_d7="negative", age_days=7, wr_attempts=1)
    log.write("recheck6", hid=hid(45), salt_ver=1, r6_skipped=False, r6_readable=True, r6_d1a_state="PASS", r6_h_state="PASS", r6_cost_usd=0.0006)
    log.write("recheck6", hid=hid(46), salt_ver=1, r6_skipped=True)
    log.write("refusal", caller="owner", code="spend_cap")
    log.write("breaker", kind="errors3", state="open")
    assert log.rejected == 0


@pytest.fixture
def text(tmp_path):
    write_log(tmp_path)
    return report.build(report.load(tmp_path), YEAR, WEEK)


@pytest.mark.parametrize("line", [
    "calls answered 50 distinct ids 50", "readable 45", "unreadable 5", "unreadable gone 3", "unreadable proxy_refused 2", "proxy_refused range private 2",
    "sonnet routed 15", "haiku HOLD overrode to pass 5", "haiku PASS turned to hold 0",
    "d1a decision hold 15", "d1a decision pass 35", "d1a holds excluding unreadable 10",
    "hold_rate with unreadable 30.0%", "hold_rate without unreadable 22.2%",
    "web_risk d0 positive 4", "web_risk d7 positive 2", "web_risk d7 negative 6", "web_risk d7 pending 42",
    "d1a hold web_risk d0 positive 4", "d1a unconfirmed holds 6", "d1a misses pass web_risk positive 2",       # readable pages only
    "haiku alone unconfirmed holds 11", "haiku alone misses pass web_risk positive 2",
    "caller owner unconfirmed holds 6 of 45 readable 13.3% upper bound not a false-positive rate",
    "unreadable_holds 5 web_risk d0 positive 0 web_risk d7 positive 0",
    "p05 3 holds 3", "p15 thin 10 holds 10",
    "d1a pass injection 1", "d1a pass truncated 1", "sonnet PASS injection 1",
    "recheck6 rechecked 1 skipped 1 pending 3", "recheck6 became readable 1", "recheck6 pass 1 hold 0",
    "cost spend_usd 0.1386", "cost per_1000_readable_usd 3.0667", "cost spend_cap_refusals 1",
    "latency capture_s median 30.0 p95 30.0", "latency sonnet_s median 1.7 p95 1.7", "breaker errors3 open 1",
])
def test_counts(text, line):
    assert line in text.splitlines()


def test_reading_rules_and_decision_4_sentence(text):
    assert report.DECISION_4 in text and all(r in text for r in report.RULES)


def test_no_reference_figures_and_the_query_cut_is_named(text):
    """No reference figures from other runs in the weekly report; the query-string cut is named."""
    assert "54 of 66" not in text and "lift-2" not in text
    assert "without its query string" in text


def test_small_groups_get_no_percentage(tmp_path):
    write_log(tmp_path)
    ev = [e for e in report.load(tmp_path) if e["event"] != "scan" or e["hid"] < hid(20)]       # 20 scans: under 30
    assert "hold_rate with unreadable n/a" in report.build(ev, YEAR, WEEK)


def test_other_weeks_are_not_counted(tmp_path):
    write_log(tmp_path)
    assert "calls answered 0 distinct ids 0" in report.build(report.load(tmp_path), YEAR, WEEK + 1)


def test_a_leaky_value_aborts_the_report(tmp_path):
    write_log(tmp_path)
    ev = report.load(tmp_path)
    ev[0]["unreadable_reason"], ev[0]["readable"] = "login.brandx.example", False      # bypasses the writer on purpose
    with pytest.raises(ValueError):
        report.build(ev, YEAR, WEEK)


def test_cli_report(tmp_path, monkeypatch, capsys):
    write_log(tmp_path)
    monkeypatch.setenv("LLMURL_DATA_DIR", str(tmp_path))
    assert cli.main(["report", "--week", "%d-W%02d" % (YEAR, WEEK)]) == 0
    assert "calls answered 50" in capsys.readouterr().out


def test_could_not_scan_is_counted_apart_from_holds_and_enters_the_recheck_population(tmp_path):
    log = LogWriter(tmp_path, clock=lambda: T)
    base = dict(salt_ver=1, caller="owner", wr_d0_date="2026-11-03", wr_d0="negative", cost_usd=0)
    log.write("scan", hid=hid(0), decision="could_not_scan", reason="page_empty", readable=True, d1a_state="UNREAD", **base)
    log.write("scan", hid=hid(1), decision="could_not_scan", reason="unreadable_gone", readable=False, unreadable_reason="gone", d1a_state="UNREAD", **base)
    log.write("scan", hid=hid(2), decision="hold", reason="hold_sonnet_verdict", readable=True, d1a_state="HOLD", h_state="HOLD", s_state="HOLD", **base)
    log.write("recheck6", hid=hid(0), salt_ver=1, r6_skipped=False, r6_readable=True, r6_d1a_state="UNREAD", r6_cost_usd=0)
    assert log.rejected == 0
    out = report.build(report.load(tmp_path), YEAR, WEEK)
    for line in ("could_not_scan 2", "could_not_scan reason page_empty 1", "d1a holds excluding unreadable 1", "d1a decision hold 1",
                 "recheck6 rechecked 1 skipped 0 pending 1"):
        assert line in out.splitlines()
