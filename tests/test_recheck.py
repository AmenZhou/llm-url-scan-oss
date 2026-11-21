"""Day-7 Web Risk recheck and the 6 h recheck: fake clock, mocked Web Risk, the store's real encryption, nothing on the network."""
import asyncio
from datetime import datetime, timedelta, timezone

from fastapi.testclient import TestClient

from llm_url_scan import recheck
from llm_url_scan.app import create_app
from llm_url_scan.capture import StubCapture
from llm_url_scan.logs import LogWriter, check_line
from llm_url_scan.store import RecheckStore
from conftest import ADDR, HOST, MARKER, FakeClient, FakeWebRisk, answer, page, resp, unreadable

T0 = datetime(2026, 11, 2, 9, 0, 0, tzinfo=timezone.utc)


def scanned(make, cap=None, client=None):
    """One scan at T0; -> (stack, store with the private key, log writer)."""
    st = make(capture=cap, client=client or FakeClient(haiku=[resp(answer("benign"))]))
    st.svc.clock = lambda: T0
    asyncio.run(st.svc.scan(ADDR, "owner"))
    store = RecheckStore(st.cfg.data_dir / "recheck.sqlite", private=st.private)
    return st, store, LogWriter(st.cfg.data_dir)


def no_r6(*a):
    raise AssertionError("no 6 h recheck expected")


def clean(st):
    text = st.log_text()
    assert all(check_line(l) == [] for l in text.splitlines())
    for secret in (ADDR, HOST, MARKER, "Zq81vKQ"):
        assert secret not in text


def test_day7_checks_once_in_window_then_deletes_the_address(make):
    st, store, log = scanned(make)
    wr = FakeWebRisk("positive")
    assert recheck.run_once(store, wr, log, T0 + timedelta(days=3), no_r6)["d7"] == 0 and wr.calls == []
    n = recheck.run_once(store, wr, log, T0 + timedelta(days=7, hours=1), no_r6)
    assert n["d7"] == 1 and wr.calls == [ADDR] and store.rows() == []
    ev = [e for e in st.log_events() if e["event"] == "recheck"]
    assert len(ev) == 1 and ev[0]["wr_d7"] == "positive" and ev[0]["age_days"] == 7 and ev[0]["hid"] == st.log_events()[0]["hid"]
    assert recheck.run_once(store, wr, log, T0 + timedelta(days=7, hours=2), no_r6)["d7"] == 0 and len(wr.calls) == 1
    clean(st)


def test_a_rescan_keeps_the_first_row(make):
    """Review finding 8: day 7 counts from the first scan; a later scan of the same address does not reset it."""
    st, store, log = scanned(make, client=FakeClient(haiku=[resp(answer("benign")), resp(answer("benign"))]))
    first = store.rows()[0]
    st.svc.clock = lambda: T0 + timedelta(days=3)
    asyncio.run(st.svc.scan(ADDR, "owner"))
    assert store.rows() == [first]


def test_daily_ceiling_keeps_the_row_until_day_8_then_missed(make):
    st, store, log = scanned(make)
    wr = FakeWebRisk("not_checked")
    recheck.run_once(store, wr, log, T0 + timedelta(days=7, hours=1), no_r6)
    assert len(store.rows()) == 1 and not [e for e in st.log_events() if e["event"] == "recheck"]
    recheck.run_once(store, wr, log, T0 + timedelta(days=8, hours=1), no_r6)
    ev = [e for e in st.log_events() if e["event"] == "recheck"]
    assert store.rows() == [] and [e["wr_d7"] for e in ev] == ["missed_window"] and ev[0]["wr_attempts"] == 0
    clean(st)


def test_hard_delete_after_10_days_without_a_web_risk_call(make):
    st, store, log = scanned(make)
    wr = FakeWebRisk("negative")
    n = recheck.run_once(store, wr, log, T0 + timedelta(days=11), no_r6)
    assert n["d7_missed"] == 1 and wr.calls == [] and store.rows() == []
    assert [e["wr_d7"] for e in st.log_events() if e["event"] == "recheck"] == ["missed_window"]
    clean(st)


def test_lost_key_is_missed_key_and_the_row_is_deleted(make):
    st, _, log = scanned(make)
    wrong = make(sub="other").private
    store = RecheckStore(st.cfg.data_dir / "recheck.sqlite", private=wrong)
    wr = FakeWebRisk("negative")
    recheck.run_once(store, wr, log, T0 + timedelta(days=7, hours=1), no_r6)
    assert wr.calls == [] and store.rows() == []
    assert [e["wr_d7"] for e in st.log_events() if e["event"] == "recheck"] == ["missed_key"]


def test_six_hour_recheck_runs_once_for_unknown_pages_only(make):
    st, store, log = scanned(make, cap=StubCapture({ADDR: unreadable("other", "deadline")}))
    calls = []
    take = lambda url, hid, ver: calls.append((url, hid, ver)) or True      # noqa: E731
    wr = FakeWebRisk("negative")
    recheck.run_once(store, wr, log, T0 + timedelta(hours=4), take)
    assert calls == []
    recheck.run_once(store, wr, log, T0 + timedelta(hours=6), take)
    recheck.run_once(store, wr, log, T0 + timedelta(hours=6, minutes=10), take)
    assert len(calls) == 1 and calls[0][0] == ADDR and calls[0][1] == st.log_events()[0]["hid"]
    assert len(store.rows()) == 1 and store.rows()[0][3] is None        # the day-7 row stays; the 6 h mark is cleared


def test_six_hour_recheck_not_asked_for_a_readable_pass(make):
    st, store, log = scanned(make)
    recheck.run_once(store, FakeWebRisk(), log, T0 + timedelta(hours=6), no_r6)


def test_six_hour_recheck_missed_window_is_logged_skipped(make):
    st, store, log = scanned(make, cap=StubCapture({ADDR: unreadable("gone", "dns")}))
    down = lambda *a: False      # noqa: E731
    recheck.run_once(store, FakeWebRisk(), log, T0 + timedelta(hours=6), down)
    assert store.rows()[0][3] is not None
    recheck.run_once(store, FakeWebRisk(), log, T0 + timedelta(hours=7, minutes=30), down)
    ev = [e for e in st.log_events() if e["event"] == "recheck6"]
    assert [e["r6_skipped"] for e in ev] == [True] and store.rows()[0][3] is None
    clean(st)


def test_internal_route_runs_recheck6_for_the_scheduler_token_only(make):
    cap = StubCapture({ADDR: page()})
    st = make(capture=cap, client=FakeClient(haiku=[resp(answer("benign"))]))
    c = TestClient(create_app(st.svc, st.callers))
    sched = {"Authorization": "Bearer " + (st.cfg.data_dir / "secrets" / "caller_token_scheduler").read_text()}
    body = {"url": ADDR, "hid": "a" * 64, "salt_ver": 1}
    assert c.post("/internal/recheck6", json=body, headers=st.headers).status_code == 401        # the owner token cannot
    assert c.post("/v1/scan", json={"url": ADDR}, headers=sched).status_code == 401              # the scheduler token cannot scan
    assert c.post("/internal/recheck6", json=dict(body, extra=1), headers=sched).status_code == 400
    assert c.post("/internal/recheck6", json=dict(body, hid="xyz"), headers=sched).status_code == 400
    r = c.post("/internal/recheck6", json=body, headers=sched)
    assert r.status_code == 200 and r.json() == {"ok": True} and ADDR not in r.text
    ev = [e for e in st.log_events() if e["event"] == "recheck6"]
    assert len(ev) == 1 and ev[0]["r6_skipped"] is False and ev[0]["r6_d1a_state"] == "PASS" and ev[0]["hid"] == "a" * 64
    clean(st)


def test_api_r6_posts_to_the_internal_path_and_reports_failure_as_false(monkeypatch):
    seen = {}

    class Opener:
        def open(self, req, timeout):
            seen.update(url=req.full_url, auth=req.get_header("Authorization"), timeout=timeout)
            raise OSError("down")

    monkeypatch.setattr(recheck.urllib.request, "build_opener", lambda *h: Opener())
    assert recheck.api_r6("http://api:8800", "tok")(ADDR, "a" * 64, 1) is False
    assert seen["url"] == "http://api:8800/internal/recheck6" and seen["auth"] == "Bearer tok"
