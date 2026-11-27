"""Local demo server for llm-url-scan. Standard library only. Serves demo/page.html and a tiny JSON API on loopback.

The browser sends either a page id from the fixed list below or a URL. By default a URL is accepted only if it is one of the made-up sample pages, which
only the compose test network can reach. With --open-urls any http(s) URL is accepted (run the normal stack, not the demo allowlist: the URL goes to
Anthropic and Google Web Risk). The server calls the real service API with the owner token read from the data dir. Every scan on this page is a real scan:
real capture, real judge (a few cents of Anthropic spend). Logs hold ids and status codes only; no address, exception text or page text leaves this process.

  python demo/server.py --data-dir ./data [--port 8090] [--api http://127.0.0.1:8800] [--open-urls | --bind <this machine's Wi-Fi address> [--key CODE]]
"""
import argparse
import hmac
import json
import secrets
import sys
import threading
import time
import urllib.error
import urllib.request
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

HERE = Path(__file__).resolve().parent
FX = "fx.example"
# id, title, what it is, address inside the compose test network (see demo/allowlist.json), designed outcome (decision, short why)
PAGES = [
    {"id": "ok", "title": "Long ordinary page", "what": "A long, plain page with a sign-in box.", "host": FX, "path": "/ok", "decision": "pass",
     "why": "Plain text, nothing alarming: the cheap model should pass it."},
    {"id": "short", "title": "Very short page", "what": "A page with one sentence.", "host": FX, "path": "/short", "decision": "pass",
     "why": "Short passes also go to the second model; both should agree."},
    {"id": "bank", "title": "Fake bank sign-in", "what": "An invented bank claims your account is suspended and asks for a card number.", "host": FX, "path": "/bank",
     "decision": "hold", "why": "Urgent threat plus a request for card details."},
    {"id": "redirect", "title": "Redirect to the ordinary page", "what": "Answers with a redirect to the long ordinary page.", "host": FX, "path": "/redirect",
     "decision": "pass", "why": "The capture follows the hop and reads the same page as the first card."},
    {"id": "gone", "title": "Page that is gone", "what": "Answers 404 Not Found.", "host": FX, "path": "/404", "decision": "could_not_scan",
     "why": "An unreadable page is answered could_not_scan (the ad stops) and no model runs."},
    {"id": "wall", "title": "Blocked page", "what": "Answers 403 Forbidden with a bare wall.", "host": FX, "path": "/403", "decision": "could_not_scan",
     "why": "An unreadable page is answered could_not_scan (the ad stops) and no model runs."},
    {"id": "hang", "title": "Page that never answers", "what": "Waits far longer than the capture allows. Takes several seconds.", "host": FX, "path": "/hang",
     "decision": "could_not_scan", "why": "Two tries, then could_not_scan."},
    {"id": "login", "title": "Ordinary sign-in page", "what": "Sign-in page of an invented note-taking product, Quillfisher Notes.", "host": "quillfisher.example", "path": "/login",
     "decision": "pass", "why": "A normal product page with a normal sign-in form."},
    {"id": "parcel", "title": "Parcel fee scam", "what": "An invented courier wants a card number to release a parcel.", "host": "parcelhop.example", "path": "/parcel",
     "decision": "hold", "why": "Small fee, deadline, and a request for card details."},
    {"id": "inject", "title": "Scam with a hidden message to the judge", "what": "A prize scam with off-screen and tiny text telling the reviewer to answer benign.",
     "host": "quillfisher-rewards.example", "path": "/inject", "decision": "hold", "why": "Hidden instructions should not fool the judge; the visible card request is the signal."},
]
BY_ID = {p["id"]: p for p in PAGES}
FIXTURE_PORT = 8080
URL_MAX = 2048
BODY_CAP = 2200
API_TIMEOUT = 240
# Sample links shown in --open-urls mode (the made-up pages do not exist there). Harmless, well-known pages only.
OPEN_SAMPLES = [{"title": "example.com", "url": "https://example.com/"}, {"title": "Wikipedia home page", "url": "https://www.wikipedia.org/"}]


def page_url(p):
    return "http://%s:%d%s" % (p["host"], FIXTURE_PORT, p["path"])


BY_URL = {page_url(p): p for p in PAGES}


def valid_url(u):
    """A plain http(s) address: no whitespace or control characters, a host, no user:password. The service checks it again."""
    if not isinstance(u, str) or not 1 <= len(u) <= URL_MAX or any(c.isspace() or ord(c) < 32 for c in u):
        return False
    try:
        s = urlsplit(u)
        return s.scheme in ("http", "https") and bool(s.hostname) and not s.username and not s.password
    except ValueError:
        return False


def public_pages():
    """What the browser may see: the ten made-up sample pages, with their made-up addresses."""
    return [{"id": p["id"], "title": p["title"], "what": p["what"], "url": page_url(p), "expected": {"decision": p["decision"], "why": p["why"]}} for p in PAGES]


def flags_of(a):
    views = [v for v in (a.get("haiku"), a.get("sonnet")) if isinstance(v, dict)]
    return {"readable": a.get("readable"), "unreadable_reason": a.get("unreadable_reason"), "short": a.get("short"), "models_run": a.get("models_run", []),
            "injection_text": any(v.get("injection_text") for v in views), "rules": sorted({r for v in views for r in (v.get("rules") or [])}),
            "web_risk_d0": a.get("web_risk_d0")}


def judge_match(page, decision):
    """Did the service's decision equal the designed one? A design, not a guarantee."""
    return decision == page["decision"]


class ApiClient:
    """The real service API. The token lives only in this object and in the Authorization header of the one request."""

    def __init__(self, base, token):
        self.base, self._token = base.rstrip("/"), token

    def scan(self, url):
        """-> (http status, parsed answer dict). Raises on network trouble; callers never echo that."""
        req = urllib.request.Request(self.base + "/v1/scan", json.dumps({"url": url}).encode(),
                                     {"Authorization": "Bearer " + self._token, "Content-Type": "application/json"})
        try:
            with urllib.request.build_opener(urllib.request.ProxyHandler({})).open(req, timeout=API_TIMEOUT) as r:
                return r.status, json.loads(r.read())
        except urllib.error.HTTPError as e:
            try:
                return e.code, json.loads(e.read())
            except ValueError:
                return e.code, {"error": "internal"}


def make_server(client, port, page_html=None, open_urls=False, bind="127.0.0.1", public_host=None, key=None):
    """A ThreadingHTTPServer on bind:port (0 = any). `client` has .scan(url) -> (status, dict). open_urls: accept any http(s) URL.
    public_host: an extra Host the server answers to (the address a phone uses). key: when set, every request needs it, first as ?key= on the page
    address (answered with a cookie and a redirect that drops it from the address bar), then as that cookie."""
    html = page_html if page_html is not None else (HERE / "page.html").read_text(encoding="utf-8")
    busy = threading.Lock()

    class Handler(BaseHTTPRequestHandler):
        server_version = "demo"
        sys_version = ""

        def log_message(self, *a):
            pass

        def _log(self, code):      # ids and status codes only
            print("%s %s %s" % (self.command, self.path.split("?")[0] if self.path in ("/", "/api/pages", "/api/scan") else "other", code), file=sys.stderr)

        def _allowed_hosts(self):
            p = self.server.server_address[1]
            return {"127.0.0.1:%d" % p, "localhost:%d" % p} | ({"%s:%d" % (public_host, p)} if public_host else set())

        def _authed(self):
            if not key:
                return True
            c = SimpleCookie()
            try:
                c.load(self.headers.get("Cookie", ""))
            except Exception:
                return False
            return "demo_key" in c and hmac.compare_digest(c["demo_key"].value.encode(), key.encode())

        def _redirect_home(self):
            self.send_response(302)
            self.send_header("Location", "/")
            self.send_header("Set-Cookie", "demo_key=%s; HttpOnly; SameSite=Strict; Path=/; Max-Age=86400" % key)
            self.send_header("Content-Length", "0")
            self.send_header("Cache-Control", "no-store")
            self.send_header("Referrer-Policy", "no-referrer")
            self.end_headers()
            self._log(302)

        def _send(self, code, body, ctype, nonce=None):
            data = body if isinstance(body, bytes) else body.encode()
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header("Cross-Origin-Resource-Policy", "same-origin")
            if nonce:
                self.send_header("Content-Security-Policy", "default-src 'none'; script-src 'nonce-%s'; style-src 'nonce-%s'; connect-src 'self'; "
                                 "base-uri 'none'; form-action 'none'; frame-ancestors 'none'" % (nonce, nonce))
            self.end_headers()
            self.wfile.write(data)
            self._log(code)

        def _json(self, code, obj):
            self._send(code, json.dumps(obj), "application/json; charset=utf-8")

        def _guard(self, post):
            """Host, Origin and Fetch Metadata checks. -> True when fine; otherwise has answered 403."""
            ok = self.headers.get("Host", "") in self._allowed_hosts()
            origin = self.headers.get("Origin")
            if origin is not None:
                ok = ok and origin in {"http://" + h for h in self._allowed_hosts()}
            elif post:
                ok = False
            site = self.headers.get("Sec-Fetch-Site")
            if site is not None:
                ok = ok and site in (("same-origin",) if post else ("same-origin", "none"))
            if not ok:
                self._json(403, {"error": "forbidden"})
            return ok

        def do_GET(self):
            if not self._guard(False):
                return
            path = self.path.split("?")[0]
            if key:
                given = parse_qs(urlsplit(self.path).query).get("key", [""])[0]
                if path == "/" and given and hmac.compare_digest(given.encode(), key.encode()):
                    return self._redirect_home()
                if not self._authed():
                    return self._json(403, {"error": "forbidden"})
            if path == "/":
                nonce = secrets.token_urlsafe(18)
                self._send(200, html.replace("__NONCE__", nonce), "text/html; charset=utf-8", nonce)
            elif path == "/api/pages":
                self._json(200, {"open": open_urls, "pages": [] if open_urls else public_pages(), "samples": OPEN_SAMPLES if open_urls else []})
            else:
                self._json(404, {"error": "not_found"})

        def do_POST(self):
            if not self._guard(True):
                return
            if not self._authed():
                return self._json(403, {"error": "forbidden"})
            if self.path.split("?")[0] != "/api/scan":
                return self._json(404, {"error": "not_found"})
            if self.headers.get("Content-Type", "").split(";")[0].strip().lower() != "application/json":
                return self._json(415, {"error": "bad_content_type"})
            n = self.headers.get("Content-Length", "")
            if not (n.isascii() and n.isdigit()) or int(n) > BODY_CAP:      # "²".isdigit() is True but int("²") raises
                return self._json(400, {"error": "bad_request"})
            try:
                obj = json.loads(self.rfile.read(int(n)))
            except ValueError:
                return self._json(400, {"error": "bad_request"})
            if isinstance(obj, dict) and set(obj) == {"id"}:      # a card: exact match against the fixed list
                pid = obj["id"]
                if not isinstance(pid, str) or pid not in BY_ID:
                    return self._json(400, {"error": "bad_request"})
                url, p = page_url(BY_ID[pid]), BY_ID[pid]
            elif isinstance(obj, dict) and set(obj) == {"url"}:      # the input box or a sample link
                url = obj["url"]
                if not valid_url(url):
                    return self._json(400, {"error": "bad_request"})
                p = BY_URL.get(url)
                if p is None and not open_urls:      # default mode: only the made-up sample pages reach the service
                    return self._json(400, {"error": "not_allowed_in_this_mode"})
            else:
                return self._json(400, {"error": "bad_request"})
            if not busy.acquire(blocking=False):
                return self._json(409, {"error": "busy"})
            try:
                t0 = time.monotonic()
                try:
                    status, answer = client.scan(url)
                except Exception:
                    return self._json(502, {"error": "service_unreachable"})
                ms = int((time.monotonic() - t0) * 1000)
                if status != 200 or not isinstance(answer, dict) or "decision" not in answer:
                    code = answer.get("error") if isinstance(answer, dict) and isinstance(answer.get("error"), str) and len(answer["error"]) < 40 else "internal"
                    return self._json(502, {"error": "service_refused", "service_status": status, "service_code": code})
                self._json(200, {"id": p["id"] if p else None, "title": p["title"] if p else "Your URL", "decision": answer["decision"],
                                 "reason": answer.get("reason"), "flags": flags_of(answer), "latency_ms": ms,
                                 "expected": {"decision": p["decision"], "why": p["why"]} if p else None,      # a URL of your own has no designed outcome
                                 "matched": judge_match(p, answer["decision"]) if p else None, "answer": answer})      # the address is never echoed
            finally:
                busy.release()

    return ThreadingHTTPServer((bind, port), Handler)


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--data-dir", required=True, help="the service data dir; the owner token is read from <data-dir>/secrets/caller_token_owner")
    ap.add_argument("--port", type=int, default=8090)
    ap.add_argument("--api", default="http://127.0.0.1:8800", help="the service address (the published port of the compose api)")
    ap.add_argument("--open-urls", action="store_true", help="accept any http(s) URL (run the normal stack, not the demo allowlist; the URL goes to Anthropic and Google Web Risk)")
    ap.add_argument("--bind", default="127.0.0.1", help="address to listen on. Anything but 127.0.0.1 (for example this machine's Wi-Fi address, so a phone can reach it) needs an access code and cannot be combined with --open-urls")
    ap.add_argument("--key", help="the access code for a non-loopback --bind (default: a random one, printed in the link)")
    a = ap.parse_args()
    lan = a.bind not in ("127.0.0.1", "localhost")
    if lan and a.open_urls:
        sys.exit("--bind to a network address cannot be combined with --open-urls: real-URL scanning stays on this machine")
    if a.key is not None and len(a.key) < 12:
        sys.exit("--key must be at least 12 characters")
    key = (a.key or secrets.token_urlsafe(12)) if lan else None
    try:
        token = (Path(a.data_dir) / "secrets" / "caller_token_owner").read_text().strip()
    except OSError:
        sys.exit("cannot read the owner token under --data-dir")
    srv = make_server(ApiClient(a.api, token), a.port, open_urls=a.open_urls, bind=a.bind, public_host=a.bind if lan else None, key=key)
    print("demo page on http://%s:%d/  (%s; every scan calls the real service; Ctrl-C to stop)" % (a.bind, a.port, "OPEN: any http(s) URL" if a.open_urls else "sample pages only"), file=sys.stderr)
    if lan:
        print("phone link (same network): http://%s:%d/?key=%s" % (a.bind, a.port, key), file=sys.stderr)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
