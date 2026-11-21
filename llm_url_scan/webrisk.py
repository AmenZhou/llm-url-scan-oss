"""Google Web Risk client. Logged only: it never changes a decision."""
import re
import time
import urllib.error
import urllib.parse
import urllib.request

WR_TYPES = ("MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "SOCIAL_ENGINEERING_EXTENDED_COVERAGE")
WR_URL_RX = re.compile(r"https://webrisk\.googleapis\.com/v1/uris:search\?")
ATTEMPTS = 3
KEY_VAR = "LLMURL_WEBRISK_API_KEY"


def guard(method, url):
    """Only the one allowed request shape leaves the process (the Update method is never called)."""
    if method == "GET" and WR_URL_RX.match(url):
        q = urllib.parse.parse_qs(urllib.parse.urlsplit(url).query)
        if sorted(q) == ["threatTypes", "uri"] and sorted(q["threatTypes"]) == sorted(WR_TYPES) and len(q["uri"]) == 1:
            return
    raise RuntimeError("request shape refused")


def urllib_http(method, url, headers, body=None, timeout=10):
    """-> (status, headers lower-cased, bytes); status 0 on a transport failure (the exception text is never kept: it could hold the address)."""
    req = urllib.request.Request(url, data=body, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, {k.lower(): v for k, v in r.headers.items()}, r.read()
    except urllib.error.HTTPError as e:
        return e.code, {k.lower(): v for k, v in e.headers.items()}, e.read()
    except Exception:
        return 0, {}, b""


def classify_wr(status, body):
    """-> positive | negative | error."""
    import json
    try:
        j = json.loads(body.decode("utf-8")) if status == 200 else None
    except ValueError:
        j = None
    if not isinstance(j, dict):
        return "error"
    return "positive" if (j.get("threat") or {}).get("threatTypes") else "negative"


def retry_after(hd, default):
    try:
        return float(hd.get("retry-after", default))
    except (TypeError, ValueError):
        return float(default)


class WebRisk:
    """check(url) -> positive | negative | error | not_checked. `allow()` is the daily call ceiling hook (False = not_checked)."""

    def __init__(self, key, http=urllib_http, sleep=time.sleep, allow=lambda: True):
        self.key, self.http, self.sleep, self.allow = key, http, sleep, allow

    def check(self, url):
        if not self.key:
            return "not_checked"
        st, self.attempts = "error", 0
        for attempt in range(ATTEMPTS):
            if not self.allow():
                return "not_checked" if attempt == 0 else st
            self.attempts = attempt + 1
            q =urllib.parse.urlencode([("uri", url)] + [("threatTypes", x) for x in WR_TYPES])
            full = "https://webrisk.googleapis.com/v1/uris:search?" + q
            guard("GET", full)
            status, hd, body = self.http("GET", full, {"x-goog-api-key": self.key}, None, 10)
            st = classify_wr(status, body)
            if st != "error" or status not in (0, 429) and status < 500:
                break
            if attempt < ATTEMPTS - 1:
                self.sleep(min(retry_after(hd, 2 * (attempt + 1)), 30))
        return st
