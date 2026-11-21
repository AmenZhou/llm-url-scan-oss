"""The capture worker's mapping from what the browser and the proxy reported to the unreadable reasons, with synthetic inputs (no browser).
Everything here is made up."""
import pytest

from llm_url_scan import logs
from llm_url_scan.capture_worker import PROXY_DETAIL, STATE_DETAIL, Slot, Unavailable

HTML = "<html><head><title>T</title></head><body><p>%s</p><form><input name=u></form></body></html>" % ("Welcome made up page. " * 40)


def r(**kw):
    base = {"kind": None, "err_text": "", "hops": [(200, None, None, None)], "html": HTML, "final_url": "http://page.example/", "download": None, "proxy": []}
    base.update(kw)
    return base


def res(**kw):
    return Slot._result("http://page.example/", r(**kw), 1000, 1)


def test_readable_page_has_the_sections_and_counts():
    d = res()
    assert d["readable"] and d["forms"] == 1 and d["http_status_class"] == "2xx" and d["redirects"] == 0
    assert set(d["sections"]) == {"final_url", "page_meta", "page_text", "page_forms"} and "Welcome made up page." in d["sections"]["page_text"]


@pytest.mark.parametrize("kw,want", [
    (dict(kind="timeout", html=None, hops=[]), ("other", "deadline")),
    (dict(hops=[(404, None, None, None)]), ("gone", "http_404")),
    (dict(hops=[(410, None, None, None)], html="<p>x</p>"), ("gone", "http_410")),
    (dict(kind="error", html=None, hops=[(None, "net::ERR_NAME_NOT_RESOLVED", None, None)], err_text="net::ERR_NAME_NOT_RESOLVED"), ("gone", "dns")),
    (dict(kind="error", html=None, hops=[(None, "net::ERR_CONNECTION_REFUSED", None, None)], err_text="net::ERR_CONNECTION_REFUSED"), ("gone", "refused")),
    (dict(kind="error", html=None, hops=[], err_text="net::ERR_CONNECTION_TIMED_OUT"), ("gone", "unreachable")),
    (dict(html="<p>This domain is for sale</p>"), ("gone", "parked")),
    (dict(hops=[(403, None, None, None)], html="<p>No</p>"), ("site_blocked", "http_4xx")),
    (dict(html="<p>Just a moment</p>"), ("site_blocked", "bot_wall")),
    (dict(kind="error", html=None, hops=[], err_text="something else"), ("other", "unclassified")),
    (dict(kind="crash", html=None, hops=[]), ("other", "browser_crash")),
    (dict(final_url="chrome-error://chromewebdata/", html="<p>x</p>"), ("other", "unclassified")),      # a main frame that is not http or https
])
def test_unreadable_reasons(kw, want):
    d = res(**kw)
    assert (d["readable"], d["unreadable_reason"], d["unreadable_detail"]) == (False, *want) and d["sections"] == {}
    assert d["unreadable_detail"] in logs.DETAILS and d["unreadable_reason"] in logs.UNREAD_REASONS


@pytest.mark.parametrize("reason,range_class,detail", [("literal-blocked", "private", "literal_blocked"), ("name-blocked", None, "name_blocked"),
                                                         ("resolved-blocked", "loopback_or_unspecified", "resolved_blocked"), ("port-not-allowed", None, "port_not_allowed"),
                                                         ("numeric-host-noncanonical", None, "numeric_host"), ("upgrade-not-supported", None, "upgrade")])
def test_proxy_refusals_https_and_http(reason, range_class, detail):
    deny = [{"decision": "deny", "reason": reason, "range_class": range_class, "port_class": "443"}]
    https = res(kind="error", html=None, hops=[(None, "net::ERR_TUNNEL_CONNECTION_FAILED", None, None)], err_text="net::ERR_TUNNEL_CONNECTION_FAILED", proxy=deny)
    http = res(hops=[(403, None, "deny", reason)], html="<p>egress-denied: x</p>", proxy=deny)
    for d in (https, http):
        assert (d["unreadable_reason"], d["unreadable_detail"], d["range_class"]) == ("proxy_refused", detail, range_class) and d["sections"] == {}
        assert d["range_class"] in (None, *logs.RANGE_CLASSES)


def test_a_page_cannot_fake_a_refusal_and_a_late_denial_does_not_hide_a_page():
    assert res(hops=[(403, None, "deny", "name-blocked")], html=HTML, proxy=[])["readable"]      # a site sending the deny header without a buffered denial
    deny = [{"decision": "deny", "reason": "name-blocked", "range_class": None, "port_class": "80"}]
    assert res(proxy=deny)["readable"]      # a blocked sub-resource of a page that loaded


def test_proxy_dns_denial_is_gone_and_upstream_failure_is_unreachable():
    d = res(kind="error", html=None, hops=[(None, "net::ERR_TUNNEL_CONNECTION_FAILED", None, None)], err_text="net::ERR_TUNNEL_CONNECTION_FAILED",
            proxy=[{"decision": "deny", "reason": "no-address", "range_class": None, "port_class": "443"}])
    assert (d["unreadable_reason"], d["unreadable_detail"]) == ("gone", "dns")
    d = res(kind="error", html=None, hops=[(None, "net::ERR_TUNNEL_CONNECTION_FAILED", None, None)], err_text="net::ERR_TUNNEL_CONNECTION_FAILED",
            proxy=[{"decision": "error", "reason": "connect-failed", "range_class": None, "port_class": "443"}])
    assert (d["unreadable_reason"], d["unreadable_detail"]) == ("gone", "unreachable")


def test_a_proxy_limit_denial_is_our_capacity():
    with pytest.raises(Unavailable):
        res(proxy=[{"decision": "deny", "reason": "limit", "range_class": None, "port_class": "other"}])


def test_every_mapped_detail_is_in_the_log_vocabulary():
    assert set(PROXY_DETAIL.values()) | set(STATE_DETAIL.values()) <= set(logs.DETAILS)
