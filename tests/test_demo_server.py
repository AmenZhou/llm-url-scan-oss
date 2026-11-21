"""Offline tests of the demo server (demo/server.py): a fake API client, a loopback server on an ephemeral port, no Docker, no network beyond loopback."""
import http.client
import importlib.util
import io
import json
import re
import threading
from contextlib import redirect_stderr
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent


def _load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


demo = _load("demo_server", ROOT / "demo" / "server.py")
TOKEN = "tok-" + "f" * 60
ANSWER = {"decision": "hold", "reason": "hold_sonnet_cannot_tell", "advisory": True, "readable": True, "unreadable_reason": None, "models_run": ["h", "s"],
          "haiku": {"injection_text": True, "rules": ["R1"]}, "sonnet": {"injection_text": False, "rules": ["R2"]}, "short": False, "web_risk_d0": "negative"}


class FakeClient:
    def __init__(self, result=(200, ANSWER), exc=None):
        self.calls, self.result, self.exc, self.gate = [], result, exc, None

    def scan(self, url):
        self.calls.append(url)
        if self.gate:
            self.gate.wait(5)
        if self.exc:
            raise self.exc
        return self.result


@pytest.fixture
def srv():
    made = []

    def start(client):
        s = demo.make_server(client, 0)
        threading.Thread(target=s.serve_forever, daemon=True).start()
        made.append(s)
        return s, s.server_address[1]
    yield start
    for s in made:
        s.shutdown()
        s.server_close()


def call(port, method, path, body=None, headers=None, host=None):
    c = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
    h = {"Host": host or "127.0.0.1:%d" % port}
    h.update(headers or {})
    c.putrequest(method, path, skip_host=True, skip_accept_encoding=True)
    for k, v in h.items():
        c.putheader(k, v)
    data = body.encode() if isinstance(body, str) else body
    if data is not None:
        c.putheader("Content-Length", str(len(data)))
    c.endheaders(data)
    r = c.getresponse()
    out = (r.status, dict(r.getheaders()), r.read().decode())
    c.close()
    return out


def post(port, obj, **kw):
    h = {"Content-Type": "application/json", "Origin": "http://127.0.0.1:%d" % port}
    h.update(kw.pop("headers", {}))
    return call(port, "POST", "/api/scan", json.dumps(obj) if not isinstance(obj, str) else obj, h, **kw)


def test_scan_maps_id_to_fixture_address_and_returns_the_answer(srv):
    c = FakeClient()
    _, port = srv(c)
    st, _, body = post(port, {"id": "bank"})
    j = json.loads(body)
    assert st == 200 and c.calls == ["http://fx.example:8080/bank"]
    assert (j["decision"], j["reason"], j["matched"]) == ("hold", "hold_sonnet_cannot_tell", True) and j["answer"] == ANSWER
    assert j["flags"]["injection_text"] is True and j["flags"]["rules"] == ["R1", "R2"] and isinstance(j["latency_ms"], int)
    assert j["expected"]["decision"] == "hold"


@pytest.mark.parametrize("bad", [{"id": "nope"}, {"id": "BANK"}, {"id": "bank "}, {"id": 1}, {"id": ["bank"]}, {"url": "http://example.com/"}, {"id": "bank", "url": "http://x/"}, [], "not json"])
def test_unknown_id_or_any_other_shape_is_400_and_the_client_is_never_called(srv, bad):
    c = FakeClient()
    _, port = srv(c)
    assert post(port, bad)[0] == 400 and c.calls == []


def test_second_scan_while_busy_is_409(srv):
    c = FakeClient()
    c.gate = threading.Event()
    _, port = srv(c)
    first = []
    t = threading.Thread(target=lambda: first.append(post(port, {"id": "ok"})[0]))
    t.start()
    while not c.calls:
        pass
    assert post(port, {"id": "short"})[0] == 409 and len(c.calls) == 1
    c.gate.set()
    t.join()
    assert first == [200]
    assert post(port, {"id": "short"})[0] == 200      # free again


def test_host_origin_and_fetch_metadata_are_checked(srv):
    c = FakeClient()
    _, port = srv(c)
    assert post(port, {"id": "ok"}, host="evil.example")[0] == 403
    assert post(port, {"id": "ok"}, host="127.0.0.1")[0] == 403      # wrong port form
    assert post(port, {"id": "ok"}, headers={"Origin": "http://evil.example"})[0] == 403
    assert post(port, {"id": "ok"}, headers={"Sec-Fetch-Site": "cross-site"})[0] == 403
    assert post(port, {"id": "ok"}, headers={"Sec-Fetch-Site": "same-site"})[0] == 403
    assert call(port, "POST", "/api/scan", '{"id":"ok"}', {"Content-Type": "application/json"})[0] == 403      # no Origin on a POST
    assert call(port, "GET", "/", headers={"Origin": "http://evil.example"})[0] == 403
    assert call(port, "GET", "/", host="evil.example")[0] == 403
    assert call(port, "GET", "/", headers={"Sec-Fetch-Site": "cross-site"})[0] == 403
    assert c.calls == []
    assert post(port, {"id": "ok"}, host="localhost:%d" % port, headers={"Origin": "http://localhost:%d" % port, "Sec-Fetch-Site": "same-origin"})[0] == 200
    assert call(port, "GET", "/", headers={"Sec-Fetch-Site": "none"})[0] == 200      # typed into the address bar


def test_content_type_must_be_json(srv):
    c = FakeClient()
    _, port = srv(c)
    assert post(port, {"id": "ok"}, headers={"Content-Type": "text/plain"})[0] == 415
    assert post(port, {"id": "ok"}, headers={"Content-Type": "application/json; charset=utf-8"})[0] == 200
    assert call(port, "POST", "/api/scan", "x" * 2000, {"Content-Type": "application/json", "Origin": "http://127.0.0.1:%d" % port})[0] == 400


def test_csp_nonce_is_fresh_per_response_and_used_by_every_script_and_style(srv):
    _, port = srv(FakeClient())
    nonces = []
    for _ in range(2):
        st, h, body = call(port, "GET", "/")
        n = re.search(r"script-src 'nonce-([^']+)'", h["Content-Security-Policy"]).group(1)
        nonces.append(n)
        assert st == 200 and "__NONCE__" not in body and body.count('nonce="%s"' % n) == body.count("<script") + body.count("<style")
        assert "default-src 'none'" in h["Content-Security-Policy"] and "unsafe-inline" not in h["Content-Security-Policy"] and "http" not in h["Content-Security-Policy"]
    assert nonces[0] != nonces[1] and len(nonces[0]) >= 16


def test_page_has_no_external_resources_and_no_inline_handlers():
    html = (ROOT / "demo" / "page.html").read_text()
    assert not re.search(r"(src|href)=[\"']?https?:", html) and not re.search(r"\son[a-z]+=", html) and "<link" not in html
    assert len(re.findall(r"<script", html)) == 1 and 'nonce="__NONCE__"' in html


def test_token_never_appears_in_any_response_or_log(srv):
    c = demo.ApiClient("http://127.0.0.1:1", TOKEN)      # nothing listens there: the call fails and must not echo anything
    _, port = srv(c)
    err = io.StringIO()
    seen = []
    with redirect_stderr(err):
        seen.append(call(port, "GET", "/"))
        seen.append(call(port, "GET", "/api/pages"))
        seen.append(post(port, {"id": "ok"}))
        seen.append(post(port, {"id": "zzz"}))
        seen.append(call(port, "GET", "/missing"))
    for st, h, body in seen:
        assert TOKEN not in body and TOKEN not in json.dumps(h)
    assert TOKEN not in err.getvalue()
    assert [s[0] for s in seen] == [200, 200, 502, 400, 404]


def test_no_exception_text_leaks_when_the_client_raises(srv):
    c = FakeClient(exc=RuntimeError("secret detail fx.example/ok Bearer abc"))
    _, port = srv(c)
    err = io.StringIO()
    with redirect_stderr(err):
        st, _, body = post(port, {"id": "ok"})
        assert post(port, {"id": "ok"})[0] == 502      # the busy lock was released
    assert st == 502 and json.loads(body) == {"error": "service_unreachable"}
    for bad in ("secret detail", "fx.example", "Bearer", "RuntimeError", "Traceback"):
        assert bad not in body and bad not in err.getvalue()


def test_service_refusal_passes_only_a_short_code(srv):
    _, port = srv(FakeClient(result=(429, {"error": "daily_cap"})))
    st, _, body = post(port, {"id": "ok"})
    assert st == 502 and json.loads(body) == {"error": "service_refused", "service_status": 429, "service_code": "daily_cap"}
    _, port2 = srv(FakeClient(result=(500, {"error": "x" * 500})))
    assert json.loads(post(port2, {"id": "ok"})[2])["service_code"] == "internal"


def test_logs_hold_only_ids_and_status_codes_not_addresses(srv):
    _, port = srv(FakeClient())
    err = io.StringIO()
    with redirect_stderr(err):
        post(port, {"id": "bank"})
        call(port, "GET", "/api/pages?x=fx.example")
    out = err.getvalue()
    assert "fx.example" not in out and "bank" not in out and "/api/scan 200" in out


def test_pages_list_hides_addresses(srv):
    _, port = srv(FakeClient())
    body = call(port, "GET", "/api/pages")[2]
    assert "example" not in body and "http" not in body
    assert [p["id"] for p in json.loads(body)["pages"]] == [p["id"] for p in demo.PAGES]


def test_expectation_match_logic():
    bank, ok = demo.BY_ID["bank"], demo.BY_ID["ok"]
    assert demo.judge_match(bank, "hold") and not demo.judge_match(bank, "pass")
    assert demo.judge_match(ok, "pass") and not demo.judge_match(ok, "hold")
    assert demo.flags_of({"readable": False, "unreadable_reason": "gone", "models_run": []})["injection_text"] is False


def test_every_demo_page_has_an_allowlist_entry_and_a_compose_alias():
    allow = json.loads((ROOT / "demo" / "allowlist.json").read_text())
    names = {(e["name"], e["port"]) for e in allow}
    compose = (ROOT / "demo" / "docker-compose.demo.yml").read_text()
    for p in demo.PAGES:
        assert (p["host"], demo.FIXTURE_PORT) in names, p["id"]
        assert p["host"] in compose, p["id"]
    assert all(n.endswith(".example") for n, _ in names)      # reserved name: resolves nowhere outside the compose network
    assert {e["name"] for e in json.loads((ROOT / "tests" / "stack" / "allowlist.json").read_text())} <= {n for n, _ in names}
    assert len({p["id"] for p in demo.PAGES}) == len(demo.PAGES) == 10


def test_fixtures_serve_every_demo_path_with_the_right_content():
    fx = _load("demo_fixtures", ROOT / "tests" / "stack" / "fixtures.py")
    s = fx.S(("127.0.0.1", 0), fx.H)
    threading.Thread(target=s.serve_forever, daemon=True).start()
    try:
        def get(path):
            c = http.client.HTTPConnection("127.0.0.1", s.server_address[1], timeout=5)
            c.request("GET", path)
            r = c.getresponse()
            out = (r.status, r.getheader("Location"), r.read().decode())
            c.close()
            return out
        paths = {p["path"] for p in demo.PAGES} - {"/hang"}      # /hang sleeps by design
        assert {get(p)[0] for p in paths} == {200, 302, 403, 404}
        assert get("/redirect")[:2] == (302, "/ok") and get("/403")[0] == 403 and get("/404")[0] == 404
        assert "Sign in" in get("/login")[2] and 'type="password"' in get("/login")[2] and "card" not in get("/login")[2].lower()
        assert "card" in get("/parcel")[2].lower() and "ParcelHop" in get("/parcel")[2]
        inj = get("/inject")[2]
        assert "left:-9999px" in inj and "font-size:1px" in inj and "benign" in inj and "card" in inj.lower()
    finally:
        s.shutdown()
        s.server_close()
    for p in demo.PAGES:      # invented names only
        assert p["host"].endswith(".example")
