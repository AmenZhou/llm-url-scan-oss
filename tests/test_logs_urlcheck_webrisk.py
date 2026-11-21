"""Log writer and leak guard, URL validation, Web Risk client."""
import json
import os
import stat
import urllib.parse
from datetime import datetime, timezone

import pytest

from llm_url_scan.logs import LogWriter, check_line, check_text
from llm_url_scan.urlcheck import UrlRejected, internal_host, validate_url
from llm_url_scan.webrisk import ATTEMPTS, WR_TYPES, WebRisk, classify_wr, guard

H64 = "ab" * 32


def line(**kw):
    rec = {"ts": "2026-11-20T12:00:00Z", "event": "scan"}
    rec.update(kw)
    return json.dumps(rec)


def test_guard_accepts_allowed_values():
    assert check_line(line(hid=H64, salt_ver=1, caller="owner", decision="hold", reason="hold_sonnet_verdict", readable=True, text_chars=812,
                           h_state="HOLD", h_rules=["R1", "R3"], p15="thin", h_cost_usd=0.00058, wr_d0="negative", wr_d0_date="2026-11-20",
                           h_model="claude-haiku-5-5", h_request_id="msg_01AbC", service_version="0.1.0")) == []


@pytest.mark.parametrize("kw", [
    {"address": "https://login.brandx.example/a"},               # key not allowed
    {"decision": "https://login.brandx.example/a"},              # value not an enum member
    {"reason": "page says Welcome to Brandx"},
    {"hid": "login.brandx.example"},
    {"caller": "Brandx Corp"},
    {"h_rules": ["R1", "quote from the page"]},
    {"text_chars": "812"},
    {"text_chars": -1},
    {"readable": "yes"},
    {"h_cost_usd": float("nan")},
])
def test_guard_rejects_leaks(kw):
    assert check_line(line(**kw))


def test_guard_problems_never_hold_the_value():
    probs = check_line(line(decision="SECRETVALUE-123", address_x="SECRETVALUE-456"))
    assert probs and "SECRETVALUE" not in " ".join(probs)


def test_guard_rejects_bad_header_and_non_json():
    assert check_line("not json") == ["not_json"]
    assert check_line(json.dumps({"event": "scan"})) == ["bad_header"]
    assert check_line(json.dumps({"ts": "2026-11-20T12:00:00Z", "event": "other"})) == ["bad_header"]


def test_copied_token_rule_on_report_style_text():
    assert check_text("scan 12 hold=3 pass=9 0.25 " + H64[:12]) == []
    assert check_text("scan 12 login.brandx.example") == [(1, 3)]


def test_writer_writes_a_0600_file_and_drops_failing_lines(tmp_path):
    clock = lambda: datetime(2026, 11, 20, 12, 0, tzinfo=timezone.utc)      # noqa: E731
    w = LogWriter(tmp_path, clock)
    assert w.write("scan", hid=H64, decision="pass") is True
    assert w.write("scan", decision="https://leak.brandx.example/") is False
    assert w.write("scan", unknown_key=1) is False
    assert w.rejected == 2
    f = tmp_path / "scan-2026-11.jsonl"
    assert stat.S_IMODE(os.stat(f).st_mode) == 0o600
    text = f.read_text()
    assert text.count("\n") == 1 and "leak" not in text
    assert json.loads(text)["ts"] == "2026-11-20T12:00:00Z"


@pytest.mark.parametrize("url", [
    "https://shop.brandx.example/a?b=1", "http://shop.brandx.example:8080/", "https://bücher.example/x", "http://93.184.216.34/a",
    "http://[2606:4700:4700::1111]/", "https://a.b.c.brandx.example/p#f",
])
def test_valid_urls(url):
    assert validate_url(url) == url


@pytest.mark.parametrize("url", [
    "", "ftp://shop.brandx.example/", "javascript:alert(1)", "//shop.brandx.example/", "shop.brandx.example/a", "http://",
    "https://user:pw@shop.brandx.example/", "https://user@shop.brandx.example/", "http://shop.brandx.example\\@evil.example/", "http://a.example/ x",
    "http://a.example/\x00", "http://a.example/\n", "http://a.example:99999/", "http://a.example:abc/", "http://" + "a" * 2050 + ".example/",
    # internal targets, by spelling alone (no DNS)
    "http://127.0.0.1/", "http://10.1.2.3/", "http://192.168.0.1/", "http://169.254.169.254/latest/meta-data", "http://172.16.0.9/", "http://100.64.0.1/",
    "http://0.0.0.0/", "http://[::1]/", "http://[fd00::1]/", "http://[fe80::1]/", "http://[::ffff:127.0.0.1]/", "http://[64:ff9b::7f00:1]/",
    "http://2130706433/", "http://0x7f.0.0.1/", "http://127.1/", "http://010.1.1.1/",
    "http://localhost/", "http://intranet/", "http://printer.local/", "http://db.internal/", "http://host.docker.internal/", "http://x.test/",
    "http://x.invalid/", "http://svc.cluster.local/", "http://nas.home.arpa/", "http://localhost./",
    "http://192.0.0.9/", "http://224.0.0.1/", "http://239.1.1.1/", "http://[2001:1::1]/",      # kept in step with the egress proxy's classifier
])
def test_rejected_urls(url):
    with pytest.raises(UrlRejected) as e:
        validate_url(url)
    assert str(e.value) == ""            # no text, nothing to echo


def test_non_string_is_rejected():
    with pytest.raises(UrlRejected):
        validate_url(None)
    assert internal_host("shop.brandx.example") is False


# ---------------------------------------------------------------- Web Risk
class Http:
    def __init__(self, *answers):
        self.answers, self.seen = list(answers), []

    def __call__(self, method, url, headers, body, timeout):
        self.seen.append((method, url, headers))
        return self.answers.pop(0)


POS = (200, {}, json.dumps({"threat": {"threatTypes": ["SOCIAL_ENGINEERING"]}}).encode())
NEG = (200, {}, b"{}")


def test_classify_wr():
    assert classify_wr(*POS[::2]) == "positive" and classify_wr(200, b"{}") == "negative"
    assert classify_wr(500, b"{}") == "error" and classify_wr(200, b"not json") == "error" and classify_wr(200, b"[]") == "error"


def test_web_risk_request_shape_and_key_in_header_only():
    h = Http(POS)
    assert WebRisk("KEYVALUE12345", http=h, sleep=lambda s: None).check("https://shop.brandx.example/a?b=1") == "positive"
    method, url, headers = h.seen[0]
    assert method == "GET" and headers == {"x-goog-api-key": "KEYVALUE12345"} and "KEYVALUE" not in url
    q = urllib.parse.parse_qs(urllib.parse.urlsplit(url).query)
    assert sorted(q["threatTypes"]) == sorted(WR_TYPES) and q["uri"] == ["https://shop.brandx.example/a?b=1"]


def test_web_risk_retries_then_gives_up_as_error():
    h = Http((500, {}, b""), (0, {}, b""), (429, {"retry-after": "1"}, b""))
    slept = []
    assert WebRisk("K12345678", http=h, sleep=slept.append).check("https://a.example/") == "error"
    assert len(h.seen) == ATTEMPTS and slept == [2, 4]
    h = Http((503, {}, b""), NEG)
    assert WebRisk("K12345678", http=h, sleep=lambda s: None).check("https://a.example/") == "negative"
    h = Http((403, {}, b""))
    assert WebRisk("K12345678", http=h, sleep=lambda s: None).check("https://a.example/") == "error" and len(h.seen) == 1      # no retry on 403


def test_web_risk_ceiling_and_no_key_mean_not_checked():
    h = Http(NEG)
    assert WebRisk("K12345678", http=h, allow=lambda: False).check("https://a.example/") == "not_checked" and h.seen == []
    assert WebRisk(None, http=h).check("https://a.example/") == "not_checked"


def test_web_risk_guard_refuses_other_shapes():
    with pytest.raises(RuntimeError):
        guard("POST", "https://webrisk.googleapis.com/v1/uris:search?uri=x")
    with pytest.raises(RuntimeError):
        guard("GET", "https://webrisk.googleapis.com/v1/threatLists:computeDiff?x=1")
