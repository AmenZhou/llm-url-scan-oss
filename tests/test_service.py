"""API contract, scan flow (D1a routing, Web Risk logged only), spend cap and breakers, 6 h recheck."""
import asyncio
import json

import pytest
from fastapi.testclient import TestClient

from llm_url_scan import service as service_mod
from llm_url_scan.app import create_app
from llm_url_scan.capture import CaptureUnavailable, StubCapture
from conftest import ADDR, HOST, LONG_TEXT, MARKER, SHORT_TEXT, FakeClient, answer, page, resp, unreadable
from test_judge import Boom

H, S = "claude-haiku-5-5", "claude-sonnet-5-5"
KEYS = {"decision", "reason", "advisory", "readable", "unreadable_reason", "models_run", "haiku", "sonnet", "d1a", "web_risk_d0", "text_chars", "short",
        "cost_usd", "latency_ms", "prompt_sha256", "service_version"}


def api(st):
    return TestClient(create_app(st.svc, st.callers))


def scan(c, st, url=ADDR):
    return c.post("/v1/scan", json={"url": url}, headers=st.headers)


# ---------------------------------------------------------------- contract
def test_contract_pass_answer(make):
    st = make(client=FakeClient(haiku=[resp(answer("benign"))]))
    r = scan(api(st), st)
    body = r.json()
    assert r.status_code == 200 and set(body) == KEYS and "id" not in body          # no id
    assert (body["decision"], body["reason"], body["advisory"], body["readable"]) == ("pass", "pass_haiku", True, True)
    assert body["models_run"] == [H] and body["sonnet"] is None and body["web_risk_d0"] == "negative"
    assert body["haiku"]["state"] == "PASS" and body["d1a"] == {"state": "PASS", "routed_because": None}
    assert body["prompt_sha256"] == "1c7b2bbe7e1e8c296f7b0db4dc32b51a17dfa6ea46b67592d0c3962a865c49d7"
    for secret in (ADDR, HOST, MARKER, "Zq81vKQ"):
        assert secret not in r.text


def test_docs_routes_are_off(make):
    c = api(make())
    for p in ("/docs", "/redoc", "/openapi.json", "/docs/oauth2-redirect"):
        r = c.get(p)
        assert r.status_code == 404 and r.json() == {"error": "not_found"}


def test_health_and_status(make):
    st = make()
    c = api(st)
    assert c.get("/healthz").text == "ok"
    assert c.get("/v1/status").status_code == 401
    s = c.get("/v1/status", headers=st.headers).json()
    assert s["daily_cap_usd"] == 2.0 and s["total_cap_usd"] == 20.0 and s["open_breakers"] == []


def test_auth(make):
    st = make()
    c = api(st)
    for h in ({}, {"Authorization": "Bearer nope"}, {"Authorization": "Basic " + st.token}, {"Authorization": st.token}):
        r = c.post("/v1/scan", json={"url": ADDR}, headers=h)
        assert r.status_code == 401 and r.json() == {"error": "unauthorised"}
    assert st.capture.calls == [] and st.client.calls == []
    assert st.token not in "".join(json.dumps(e) for e in st.log_events())


def test_body_cap_4kib(make):
    st = make()
    c = api(st)
    big = json.dumps({"url": "https://a.example/" + "x" * 5000})
    r = c.post("/v1/scan", content=big, headers=st.headers)
    assert (r.status_code, r.json()) == (413, {"error": "too_large"})

    def chunks():                         # no Content-Length: the streaming limit applies
        for _ in range(10):
            yield b"y" * 1000
    r = c.post("/v1/scan", content=chunks(), headers=st.headers)
    assert (r.status_code, r.json()) == (413, {"error": "too_large"})
    assert st.capture.calls == []


@pytest.mark.parametrize("body", [b"", b"not json", b"[]", b'{"url": 5}', b'{"url": "https://a.example/", "extra": 1}', b'{"u": "https://a.example/"}'])
def test_bad_request_has_no_echo(make, body):
    st = make()
    r = api(st).post("/v1/scan", content=body, headers=st.headers)
    assert (r.status_code, r.json()) == (400, {"error": "bad_request"})


@pytest.mark.parametrize("url", ["ftp://leaky-host-1.brandx.example/", "http://127.0.0.1/", "http://localhost/leaky", "http://x.test/leaky-path", "https://u:p@leaky.brandx.example/",
                                 "http://leaky.brandx.example\\@e.example/", "http://10.0.0.5/leaky"])
def test_422_for_bad_and_internal_urls_before_anything_runs(make, url):
    st = make()
    r = scan(api(st), st, url)
    assert (r.status_code, r.json()) == (422, {"error": "url_not_allowed"})
    assert "leaky" not in r.text and st.wr.calls == [] and st.capture.calls == [] and st.client.calls == []      # not even Web Risk
    assert "leaky" not in st.log_text()


def test_unknown_route_and_method_have_no_echo(make):
    c = api(make())
    assert c.get("/v1/leaky-path").json() == {"error": "not_found"}
    assert c.get("/v1/scan").json() == {"error": "method_not_allowed"}


def test_error_path_is_class_name_only(make):
    st = make(capture=StubCapture({ADDR: RuntimeError("failed for %s %s" % (ADDR, MARKER))}))
    r = scan(api(st), st)
    assert (r.status_code, r.json()) == (500, {"error": "internal"})
    assert st.log_events()[-1] == {**st.log_events()[-1], "event": "refusal", "code": "internal", "exc": "RuntimeError", "caller": "owner"}
    assert ADDR not in st.log_text() and MARKER not in st.log_text()
    assert st.svc.ledger.spent()[0] > 0           # the unfinished call keeps its reservation


def test_capture_unavailable_is_503_and_free(make):
    st = make(capture=StubCapture({ADDR: CaptureUnavailable()}))
    r = scan(api(st), st)
    assert (r.status_code, r.json()) == (503, {"error": "capture_unavailable"})
    assert st.svc.ledger.spent() == (0.0, 0.0) and st.client.calls == []


def test_rate_limit_429_with_retry_after(make, monkeypatch):
    monkeypatch.setattr(service_mod, "RATE_PER_MIN", 2)
    st = make(client=FakeClient(haiku=[resp(answer())] * 3))
    c = api(st)
    assert [scan(c, st).status_code for _ in range(2)] == [200, 200]
    r = scan(c, st)
    assert (r.status_code, r.json()) == (429, {"error": "rate_limited"}) and int(r.headers["retry-after"]) >= 1


def test_deadline_504(make, monkeypatch):
    class Slow:
        calls = []

        async def capture(self, url):
            await asyncio.sleep(5)
    monkeypatch.setattr(service_mod, "DEADLINE_S", 0.05)
    st = make(capture=Slow())
    r = scan(api(st), st)
    assert (r.status_code, r.json()) == (504, {"error": "deadline"})
    assert st.svc.ledger.spent()[0] > 0


# ---------------------------------------------------------------- D1a routing
@pytest.mark.parametrize("reason", ["gone", "site_blocked", "proxy_refused", "other"])
def test_policy_a_unreadable_is_a_hold_with_no_model_call(make, reason):
    st = make(capture=StubCapture({ADDR: unreadable(reason, "dns" if reason == "gone" else None)}))
    body = scan(api(st), st).json()
    assert (body["decision"], body["reason"], body["readable"], body["unreadable_reason"]) == ("hold", "unreadable_" + reason, False, reason)
    assert body["models_run"] == [] and body["haiku"] is None and body["d1a"]["state"] == "UNREAD" and body["cost_usd"] == 0.0
    assert st.client.calls == [] and st.svc.ledger.spent() == (0.0, 0.0)
    (ev,) = st.log_events()
    assert (ev["decision"], ev["reason"], ev["d1a_state"], ev["unreadable_reason"]) == ("hold", "unreadable_" + reason, "UNREAD", reason)


def test_haiku_answer_is_logged_beside_d1a(make):
    st = make(client=FakeClient(haiku=[resp(answer("phishing", quotes=[MARKER], rules=["R1"], brand="Brandx"))], sonnet=[resp(answer("benign"))]),
              capture=StubCapture({ADDR: page(text=LONG_TEXT)}))
    body = scan(api(st), st).json()
    assert (body["decision"], body["reason"]) == ("pass", "pass_sonnet_overrode_hold")
    assert body["haiku"]["state"] == "HOLD" and body["sonnet"]["state"] == "PASS" and body["d1a"] == {"state": "PASS", "routed_because": "h_hold"}
    (ev,) = st.log_events()
    assert (ev["h_state"], ev["h_outcome"], ev["h_verdict"], ev["h_rules"], ev["h_brand_present"]) == ("HOLD", "HOLD", "phishing", ["R1"], True)
    assert (ev["s_state"], ev["d1a_state"], ev["s_routed_because"], ev["decision"]) == ("PASS", "PASS", "h_hold", "pass")
    assert ev["h_model"] == H and ev["s_model"] == S and ev["h_in_tok"] == 2000 and ev["h_request_id"] == "msg_test01"


def test_long_haiku_pass_skips_sonnet_short_pass_calls_it(make):
    st = make(client=FakeClient(haiku=[resp(answer())]))
    assert scan(api(st), st).json()["models_run"] == [H]
    assert st.client.models_called() == [H]
    st = make(client=FakeClient(haiku=[resp(answer())], sonnet=[resp(answer())]), capture=StubCapture({ADDR: page(text=SHORT_TEXT)}))
    body = scan(api(st), st).json()
    assert (body["reason"], body["short"], body["models_run"]) == ("pass_sonnet_confirmed_short", True, [H, S])
    assert st.client.models_called() == [H, S]
    # both models get the identical message
    assert st.client.calls[0]["messages"] == st.client.calls[1]["messages"]


def test_sonnet_cannot_tell_is_held(make):
    st = make(client=FakeClient(haiku=[resp(answer("cannot_tell"))], sonnet=[resp(answer("cannot_tell"))]))
    body = scan(api(st), st).json()
    assert (body["decision"], body["reason"], body["d1a"]) == ("hold", "hold_sonnet_cannot_tell", {"state": "CANNOT", "routed_because": "h_cannot"})


def test_web_risk_is_logged_and_never_changes_the_decision(make):
    st = make(client=FakeClient(haiku=[resp(answer())]), wr="positive")
    body = scan(api(st), st).json()
    assert body["decision"] == "pass" and body["web_risk_d0"] == "positive"
    (ev,) = st.log_events()
    assert ev["wr_d0"] == "positive" and ev["decision"] == "pass" and len(ev["wr_d0_date"]) == 10
    st = make(client=FakeClient(haiku=[resp(answer("phishing", quotes=[MARKER], rules=["R1"])), ], sonnet=[resp(answer("phishing", quotes=[MARKER], rules=["R1"]))]), wr="negative")
    assert scan(api(st), st).json()["decision"] == "hold"


def test_patterns_and_forms_are_logged_as_flags(make):
    st = make(client=FakeClient(haiku=[resp(answer())]), capture=StubCapture({ADDR: page(text=LONG_TEXT + " Please sign in to continue. Your account has been suspended.")}))
    scan(api(st), st)
    (ev,) = st.log_events()
    assert (ev["p12"], ev["p13"], ev["p05"], ev["p15"]) == (1, 1, 0, "longer")


def test_query_is_cut_in_the_model_message(make):
    st = make(client=FakeClient(haiku=[resp(answer())]))
    scan(api(st), st)
    msg = st.client.calls[0]["messages"][0]["content"]
    assert "Zq81vKQ" not in msg and "?[query" in msg


# ---------------------------------------------------------------- spend cap, reservation and breakers
def test_spend_cap_stops_before_any_work(make):
    st = make(daily_cap=0.05)
    r = scan(api(st), st)
    assert (r.status_code, r.json()) == (503, {"error": "spend_cap"})
    assert st.capture.calls == [] and st.wr.calls == [] and st.client.calls == []
    assert [e["event"] for e in st.log_events()] == ["refusal"]


def test_total_cap(make):
    st = make(total_cap=0.1, client=FakeClient(haiku=[resp(answer())]))
    assert scan(api(st), st).status_code == 503


def test_cap_applies_across_calls_with_measured_cost(make):
    st = make(daily_cap=0.2, client=FakeClient(haiku=[resp(answer())] * 3))
    c = api(st)
    assert [scan(c, st).status_code for _ in range(3)] == [200, 200, 200]      # reservations are replaced by the measured cost (USD 0.00025)
    assert st.svc.ledger.spent()[0] == pytest.approx(3 * 0.00025)


def test_large_message_tops_up_the_reservation_and_can_hit_the_cap(make):
    st = make(daily_cap=0.125, client=FakeClient(haiku=[resp(answer())]), capture=StubCapture({ADDR: page(text="w " * 3500)}))
    r = scan(api(st), st)
    assert (r.status_code, r.json()) == (503, {"error": "spend_cap"}) and st.client.calls == []       # the byte bound needs more than the cap allows
    assert st.svc.ledger.spent()[0] == 0.0                                                            # no model ran: nothing is charged


def test_open_breaker_refuses_and_owner_resume_lifts_it(make, monkeypatch, capsys):
    st = make(client=FakeClient(haiku=[resp(answer())]))
    st.svc.ledger.open_breaker("meancost")
    c = api(st)
    r = scan(c, st)
    assert (r.status_code, r.json()) == (503, {"error": "paused"}) and st.capture.calls == []
    monkeypatch.setenv("LLMURL_DATA_DIR", str(st.cfg.data_dir))
    from llm_url_scan import cli
    assert cli.main(["resume", "meancost"]) == 0 and "resumed meancost" in capsys.readouterr().out
    assert scan(c, st).status_code == 200
    assert [e.get("state") for e in st.log_events() if e["event"] == "breaker"] == ["resumed"]


def test_auth_failure_from_the_provider_opens_a_breaker_and_returns_no_decision(make):
    st = make(client=FakeClient(haiku=[Boom(401)]))
    c = api(st)
    r = scan(c, st)
    assert (r.status_code, r.json()) == (503, {"error": "paused"})
    assert st.svc.ledger.open_kinds() == ["auth"]
    assert scan(c, st).status_code == 503 and len(st.client.calls) == 1                  # no second provider call


def test_first_call_400_opens_the_final_shape_breaker(make):
    st = make(client=FakeClient(haiku=[Boom(400)]))
    assert scan(api(st), st).status_code == 503
    assert st.svc.ledger.open_kinds() == ["shape400"]
    assert st.svc.ledger.resume("shape400") is False


def test_api_outage_holds_with_sonnet_failed(make):
    st = make(client=FakeClient(haiku=[Boom(500), Boom(500)], sonnet=[Boom(500), Boom(500)]))
    body = scan(api(st), st).json()
    assert (body["decision"], body["reason"]) == ("hold", "hold_sonnet_failed")
    assert body["haiku"]["outcome"] == "ERROR" and body["d1a"]["routed_because"] == "h_failed"


# ---------------------------------------------------------------- the 6 h recheck path and the sealed store
def test_unreadable_and_cannot_tell_pages_get_a_six_hour_row_others_do_not(make):
    st = make(capture=StubCapture({ADDR: unreadable("gone", "dns")}))
    scan(api(st), st)
    assert st.svc.store.rows()[0][3] is not None
    st = make(client=FakeClient(haiku=[resp(answer())]), sub="other")
    scan(api(st), st)
    assert st.svc.store.rows()[0][3] is None and st.svc.store.rows()[0][2] is not None      # day 7 always


def test_recheck6_logs_the_second_look_and_leaves_the_first_decision(make):
    st = make(capture=StubCapture({ADDR: unreadable("gone", "dns")}))
    scan(api(st), st)
    hid, ver = st.svc.store.rows()[0][:2]
    st.capture.results[ADDR] = page(text=LONG_TEXT)
    st.client.script[H] = [resp(answer())]
    assert asyncio.run(st.svc.recheck6(ADDR, hid, ver)) is True
    first, second = st.log_events()
    assert first["decision"] == "hold" and first["reason"] == "unreadable_gone"
    assert second == {**second, "event": "recheck6", "hid": hid, "r6_skipped": False, "r6_readable": True, "r6_h_state": "PASS", "r6_d1a_state": "PASS"}
    assert second["r6_cost_usd"] == pytest.approx(0.00025) and st.svc.ledger.spent()[0] == pytest.approx(0.00025)


def test_recheck6_is_skipped_when_a_breaker_or_cap_stops_it(make):
    st = make(capture=StubCapture({ADDR: page()}))
    st.svc.ledger.open_breaker("errors3")
    assert asyncio.run(st.svc.recheck6(ADDR, "a" * 64, 1)) is True
    assert st.log_events()[-1]["r6_skipped"] is True and st.capture.calls == []
    st = make(daily_cap=0.01)
    asyncio.run(st.svc.recheck6(ADDR, "a" * 64, 1))
    assert st.log_events()[-1]["r6_skipped"] is True


def test_the_store_holds_the_address_sealed_and_the_scheduler_key_reads_it(make):
    from llm_url_scan.store import RecheckStore
    st = make(client=FakeClient(haiku=[resp(answer())]))
    scan(api(st), st)
    hid, ver = st.svc.store.rows()[0][:2]
    sched = RecheckStore(st.cfg.data_dir / "recheck.sqlite", private=st.private)
    assert sched.read(hid, ver) == ADDR
    assert b"brandx" not in (st.cfg.data_dir / "recheck.sqlite").read_bytes()
