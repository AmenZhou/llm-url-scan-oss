"""LEAK TEST: fixture scans with made-up addresses through mocked Anthropic, Web Risk and capture clients, including forced exceptions.
No log line, no captured stdout or stderr, no logging record, no response body and no data-dir file (other than secrets) may hold an address,
a host, a query value, a brand string or page text."""
import json
import logging
import sys
import threading

from fastapi.testclient import TestClient

from llm_url_scan.app import NoExcFormatter, create_app, install_excepthooks
from llm_url_scan.capture import CaptureUnavailable, StubCapture
from llm_url_scan.logs import check_line
from conftest import FakeClient, FakeWebRisk, answer, page, resp, unreadable

BRAND = "Quillfisher Bank"
TEXT = "Welcome back to Quillfisher Bank. SECRET-PAGE-TEXT-4471 Please sign in to continue. " * 20
PAGE_PHRASE = "SECRET-PAGE-TEXT-4471"
ADDRS = {n: "https://%s.quillfisher-%s.example/session/%s?uid=SECRETQUERY%s" % (n, n, n, i) for i, n in enumerate(
    ("pass", "hold", "gone", "forced", "unavail", "wrfail", "short"))}
HOSTS = ["%s.quillfisher-%s.example" % (n, n) for n in ADDRS]
FORBIDDEN = list(ADDRS.values()) + HOSTS + ["quillfisher", "SECRETQUERY", PAGE_PHRASE, BRAND, "/session/", "Welcome back"]


def test_no_output_holds_an_address_host_or_page_text(make, capfd, caplog):
    caplog.set_level(logging.DEBUG)
    exc_text = "boom while fetching %s with %s" % (ADDRS["forced"], PAGE_PHRASE)
    capture = StubCapture({
        ADDRS["pass"]: page(text=TEXT, final=ADDRS["pass"]),
        ADDRS["hold"]: page(text=TEXT, final=ADDRS["hold"] + "/redirected?token=SECRETQUERY9"),
        ADDRS["gone"]: unreadable("gone", "dns"),
        ADDRS["forced"]: RuntimeError(exc_text),
        ADDRS["unavail"]: CaptureUnavailable(exc_text),
        ADDRS["wrfail"]: page(text=TEXT),
        ADDRS["short"]: page(text="Quillfisher Bank " + PAGE_PHRASE),
    })
    quote = "Welcome back to Quillfisher Bank"
    client = FakeClient(
        haiku=[resp(answer("benign")),                                                                 # pass
               resp(answer("phishing", quotes=[quote, PAGE_PHRASE], rules=["R1", "R3"], brand=BRAND)),     # hold
               resp(answer("benign"))],                                                                # short
        sonnet=[resp(answer("phishing", quotes=[quote], rules=["R1"], brand=BRAND)),                    # hold: Sonnet confirms
                resp(answer("benign", brand=BRAND))])                                                   # short pass: Sonnet confirms
    st = make(client=client, capture=capture)
    saved = sys.excepthook, threading.excepthook      # restored below
    try:
        install_excepthooks()
        app = create_app(st.svc, st.callers)
        c = TestClient(app, raise_server_exceptions=False)
        bodies = []
        for name in ("pass", "hold", "gone", "forced", "unavail", "short"):
            bodies.append(c.post("/v1/scan", json={"url": ADDRS[name]}, headers=st.headers))
        st.svc.webrisk.state = RuntimeError("web risk failed for %s" % ADDRS["wrfail"])      # a forced exception in the Web Risk client
        bodies.append(c.post("/v1/scan", json={"url": ADDRS["wrfail"]}, headers=st.headers))
        bodies.append(c.post("/v1/scan", json={"url": ADDRS["pass"].replace("https", "ftp")}, headers=st.headers))       # 422
        bodies.append(c.post("/v1/scan", content=b'{"url": "' + ADDRS["pass"].encode() + b'", "x": 1}', headers=st.headers))   # 400
        bodies.append(c.post("/v1/scan", json={"url": ADDRS["pass"]}, headers={"Authorization": "Bearer wrong-" + PAGE_PHRASE}))   # 401
        bodies.append(c.post("/v1/scan", content=b"x" * 5000, headers=st.headers))                                         # 413
        bodies.append(c.get("/v1/%s" % PAGE_PHRASE))                                                                     # 404
        assert [b.status_code for b in bodies] == [200, 200, 200, 500, 503, 200, 500, 422, 400, 401, 413, 404]
        sys.excepthook(RuntimeError, RuntimeError(exc_text), None)
        threading.excepthook(threading.ExceptHookArgs((RuntimeError, RuntimeError(exc_text), None, None)))
    finally:
        sys.excepthook, threading.excepthook = saved
    rec = logging.LogRecord("t", logging.ERROR, __file__, 1, "failed", None, (RuntimeError, RuntimeError(exc_text), None))
    formatted = NoExcFormatter("%(message)s").format(rec)
    assert formatted == "failed"

    out, err = capfd.readouterr()
    log_lines = st.log_text().splitlines()
    assert len(log_lines) >= 9
    assert all(check_line(l) == [] for l in log_lines), "a log line failed the leak guard"
    assert st.svc.log.rejected == 0

    # the log is a counts log: the Haiku answer's brand string and quotes are dropped in memory
    scans = [json.loads(l) for l in log_lines if json.loads(l)["event"] == "scan"]
    assert any(s.get("h_brand_present") for s in scans) and all(len(s["hid"]) == 64 for s in scans)

    blobs = {"stdout": out, "stderr": err, "caplog": "".join(r.getMessage() for r in caplog.records if not r.name.startswith("httpx")),
             "log": st.log_text(), "responses": "".join(b.text for b in bodies)}
    for p in st.cfg.data_dir.rglob("*"):              # every data-dir file except the generated secrets (the encrypted store and the ledger included)
        if p.is_file() and "secrets" not in p.relative_to(st.cfg.data_dir).parts:
            blobs[p.name] = p.read_bytes().decode("latin-1")
    assert {"recheck.sqlite", "ledger.sqlite"} <= set(blobs)
    for where, blob in blobs.items():
        for needle in FORBIDDEN:
            assert needle not in blob, "%s holds a forbidden string" % where
    assert err.count("unhandled RuntimeError") == 2           # the two excepthooks printed a class name and nothing else
