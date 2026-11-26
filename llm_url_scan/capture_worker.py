"""The capture worker: runs inside the isolated `capture` container (Playwright Chromium, sandbox on, its only route out is the egress proxy).

POST /capture {"url": ...} with `Authorization: Bearer <worker token>` -> the capture dict of capture.py (readable, unreadable_reason, sections, ...).
GET /sandbox -> {"sandbox": true|false, "renderers": n}   (canary).   GET /healthz -> ok.
Stdlib + playwright only: this file and pagetext.py are all the capture image holds of this project.

No address, host, page text or error message is ever printed. Playwright error text is searched in memory by classify_state and dropped.
One browser per slot; a slot is one thread because Playwright's sync API is bound to the thread that started it.
"""
import hmac
import http.client
import json
import os
import queue
import re
import sys
import threading
import time
from concurrent.futures import Future
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit

from . import pagetext as pt

SLOTS = int(os.environ.get("CAPTURE_SLOTS", "2"))
PROXY_HOST, PROXY_BASE_PORT = os.environ.get("CAPTURE_PROXY_HOST", "proxy"), int(os.environ.get("CAPTURE_PROXY_BASE_PORT", "3128"))
PAGE_MS, WAIT_MS = int(os.environ.get("CAPTURE_PAGE_TIMEOUT_MS", "60000")), int(os.environ.get("CAPTURE_WAIT_MS", "5000"))
BIND, PORT = os.environ.get("CAPTURE_BIND", "127.0.0.1"), int(os.environ.get("CAPTURE_PORT", "7100"))
TOKEN_FILE = os.environ.get("CAPTURE_TOKEN_FILE", "/run/worker/worker_token")
HTML_CAP, BODY_CAP, SLOT_WAIT_S = 2 * 1024 * 1024, 4096, 30

# proxy reason (egress-proxy.mjs) -> logs.DETAILS
PROXY_DETAIL = {"name-blocked": "name_blocked", "numeric-host-noncanonical": "numeric_host", "literal-blocked": "literal_blocked", "resolved-blocked": "resolved_blocked",
                "allowlist-pin-mismatch": "resolved_blocked", "port-not-allowed": "port_not_allowed", "bad-request": "bad_request", "method-not-allowed": "bad_request",
                "upgrade-not-supported": "upgrade"}
STATE_DETAIL = {"http-404": "http_404", "http-410": "http_410", "dns": "dns", "refused": "refused", "unreachable": "unreachable", "parked": "parked",
                "http-4xx": "http_4xx", "bot-wall": "bot_wall"}


class Unavailable(Exception):
    """Our capacity, not a page property (503)."""


def _say(kind):
    print("capture-worker %s" % kind, file=sys.stderr, flush=True)


def take_denials(slot):
    """What the proxy refused on this slot since the last call (reason, range class; no host)."""
    try:
        c = http.client.HTTPConnection(PROXY_HOST, PROXY_BASE_PORT + slot, timeout=5)
        c.request("GET", "/__take")
        r = c.getresponse()
        data = json.loads(r.read(65536))
        c.close()
        return [d for d in data.get("denials", []) if isinstance(d, dict)]
    except Exception:
        raise Unavailable() from None


def sandbox_state():
    """Chromium's sandbox is active when some child process sits in its own user namespace and runs under a second seccomp filter (Chromium's, on top of
    the container's), and no command line carries --no-sandbox. `renderers` counts those sandboxed children (the renderer rewrites its command line, so
    the process type is not readable from it)."""
    sandboxed, bad, me = 0, False, os.readlink("/proc/self/ns/user")
    for pid in filter(str.isdigit, os.listdir("/proc")):
        try:
            cmd = open("/proc/%s/cmdline" % pid, "rb").read()
            if b"--no-sandbox" in cmd:
                bad = True
            status = open("/proc/%s/status" % pid).read()
            m = re.search(r"^Seccomp_filters:\s+(\d+)$", status, re.M)
            if m and int(m.group(1)) >= 2 and os.readlink("/proc/%s/ns/user" % pid) != me:
                sandboxed += 1
        except OSError:
            continue
    return {"sandbox": sandboxed > 0 and not bad, "renderers": sandboxed}


def _unread(reason, detail, range_class, ms, tries, status_class=None):
    return {"readable": False, "unreadable_reason": reason, "unreadable_detail": detail, "range_class": range_class, "sections": {}, "capture_ms": ms, "tries": tries,
            "redirects": 0, "forms": 0, "http_status_class": status_class}


class Slot:
    """One browser. `run(url)` must be called on the slot's own thread."""

    def __init__(self, k, pw):
        self.k, self.pw, self.browser = k, pw, None

    def _launch(self):
        self.browser = self.pw.chromium.launch(
            headless=True, chromium_sandbox=True,      # sandbox on; --no-sandbox is never passed
            proxy={"server": "http://%s:%d" % (PROXY_HOST, PROXY_BASE_PORT + self.k), "bypass": "<-loopback>"},      # loopback goes through the proxy too
            args=["--disable-breakpad", "--disable-crash-reporter", "--webrtc-ip-handling-policy=disable_non_proxied_udp", "--force-webrtc-ip-handling-policy"])

    def probe(self):
        """Sandbox check on this slot: open a page (so a renderer exists) and read the sandbox state while it is open."""
        if self.browser is None or not self.browser.is_connected():
            self._launch()
        ctx = self.browser.new_context()
        try:
            ctx.new_page().goto("data:text/html,x")
            return sandbox_state()
        finally:
            ctx.close()

    def _once(self, url):
        """One try -> dict(kind, err_text, hops, html, final_url, download, proxy) with no exception text kept beyond err_text (memory only)."""
        if self.browser is None or not self.browser.is_connected():
            self._launch()
        out = {"kind": None, "err_text": "", "hops": [], "html": None, "final_url": None, "download": None, "proxy": None}
        take_denials(self.k)      # clears the buffer: a denial of an earlier try cannot taint this one
        ctx = self.browser.new_context(**self.pw.devices["Desktop Chrome"], accept_downloads=True, ignore_https_errors=True, service_workers="block", permissions=[])
        try:
            page = ctx.new_page()
            main = page.main_frame

            def on_resp(r):
                if r.request.is_navigation_request() and r.frame == main:
                    h = r.headers
                    out["hops"].append((r.status, None, h.get("x-egress-decision"), h.get("x-egress-reason")))

            def on_failed(r):
                if r.is_navigation_request() and r.frame == main:
                    out["hops"].append((None, r.failure or "", None, None))

            def on_download(d):      # cancelled after recording the extension; never saved
                name = d.suggested_filename or ""
                out["download"] = (os.path.splitext(name)[1], 0)
                try:
                    d.cancel()
                except Exception:
                    pass
            page.on("response", on_resp)
            page.on("requestfailed", on_failed)
            page.on("download", on_download)
            try:
                page.goto(url, timeout=PAGE_MS, wait_until="load")
                page.wait_for_timeout(WAIT_MS)
                out["final_url"] = page.url
                out["html"] = page.content()[:HTML_CAP]
            except Exception as e:      # message is searched here and dropped
                name, msg = type(e).__name__, str(e)
                if name == "TimeoutError":
                    out["kind"] = "timeout"
                elif "Download is starting" in msg:
                    out["download"] = out["download"] or ("", 0)
                else:
                    out["kind"], out["err_text"] = "error", msg
                    if re.search(r"Target (page, context or browser )?has been closed|crash|Browser has been closed", msg, re.I):
                        out["kind"] = "crash"
        finally:
            try:
                ctx.close()
            except Exception:
                self.browser = None
        out["proxy"] = take_denials(self.k)
        return out

    def run(self, url):
        t0, tries, res = time.monotonic(), 0, None
        while tries < 2:
            tries += 1
            try:
                res = self._once(url)
            except Unavailable:
                raise
            except Exception:
                self.browser = None
                res = {"kind": "crash", "err_text": "", "hops": [], "html": None, "final_url": None, "download": None, "proxy": []}
            if res["kind"] != "timeout":      # only a first try that ends timed out is retried
                break
        return self._result(url, res, int((time.monotonic() - t0) * 1000), tries)

    @staticmethod
    def _result(url, r, ms, tries):
        proxy, hops = r["proxy"], r["hops"]
        if any(d.get("reason") == "limit" for d in proxy):
            raise Unavailable()
        last = hops[-1] if hops else None
        denials = [d for d in proxy if d.get("decision") == "deny"]
        errs = [d for d in proxy if d.get("decision") == "error"]
        dead502 = last is not None and last[0] == 502 and last[2] == "error" and bool(errs)      # plain http: the proxy's own 502 for a dead host
        shaped = "ERR_TUNNEL_CONNECTION_FAILED" in r["err_text"] or (last is not None and last[0] == 403 and last[2] == "deny") or dead502      # a page cannot fake the buffer
        deny = denials[0] if denials and shaped else None
        err_text, kind, html = r["err_text"], r["kind"], r["html"]
        if deny is None and shaped and not denials and errs:      # proxy could not connect upstream: a dead host, not a refusal
            err_text += " ERR_CONNECTION_RESET"
        if deny is not None or (dead502 and not denials):      # the body of a proxy denial or error is never page text
            kind, html = kind or "error", None
        if kind is None and html is not None and urlsplit(r["final_url"] or "").scheme not in ("http", "https"):
            kind = "error"
        text = pt.html_to_text(html) if html is not None else None
        scan = pt.scan_page(html or "")      # a download-only link has no html
        forms = len(scan["forms"]) + len(scan["loose_fields"])
        status = [h for h in hops if h[0] is not None]
        last_status = status[-1][0] if status else None
        klass = "%dxx" % (last_status // 100) if last_status and 200 <= last_status < 600 else None
        if kind == "crash":
            return _unread("other", "browser_crash", None, ms, tries, klass)
        state, detail = pt.classify_state("timeout" if kind == "timeout" else kind, err_text, [(h[0], h[1]) for h in hops], text, forms,
                                          deny.get("reason") if deny else None, r["download"] is not None)
        if state == "timed out":
            return _unread("other", "deadline", None, ms, tries, klass)
        if state == "blocked" and detail == "proxy-denied":
            return _unread("proxy_refused", PROXY_DETAIL.get(deny["reason"], "bad_request"), deny.get("range_class"), ms, tries, klass)
        if state == "gone":
            return _unread("gone", STATE_DETAIL[detail], None, ms, tries, klass)
        if state == "blocked":
            return _unread("site_blocked", STATE_DETAIL[detail], None, ms, tries, klass) if detail in STATE_DETAIL else _unread("other", "unclassified", None, ms, tries, klass)
        built = pt.build_page(url, r["final_url"], last_status, max(0, len(status) - 1), scan["title"], text or "", scan, pt.extract_buttons(html or ""), r["download"])
        return {"readable": True, "unreadable_reason": None, "unreadable_detail": None, "range_class": None, "sections": built["sections"], "capture_ms": ms,
                "tries": tries, "redirects": max(0, len(status) - 1), "forms": forms, "http_status_class": klass}


class Pool:
    def __init__(self):
        self.jobs = [queue.Queue() for _ in range(SLOTS)]
        self.free = queue.Queue()
        self.ready = [threading.Event() for _ in range(SLOTS)]
        self.failed = threading.Event()
        for k in range(SLOTS):
            threading.Thread(target=self._loop, args=(k,), daemon=True).start()

    def _loop(self, k):
        from playwright.sync_api import sync_playwright
        try:
            with sync_playwright() as pw:
                slot = Slot(k, pw)
                slot._launch()
                ctx = slot.browser.new_context()      # the sandbox must be demonstrably active in this slot before it takes work
                ctx.new_page().goto("data:text/html,x")
                if not sandbox_state()["sandbox"]:
                    raise RuntimeError
                ctx.close()
                self.ready[k].set()
                self.free.put(k)
                while True:
                    url, fut = self.jobs[k].get()
                    try:
                        fut.set_result(slot.probe() if url is None else slot.run(url))
                    except Exception as e:
                        fut.set_exception(e)
                    self.free.put(k)
        except Exception as e:
            _say("slot %d stopped: %s" % (k, type(e).__name__))
            self.failed.set()

    def probe(self):
        """Sandbox state with a page open in every slot (canary): sandboxed only if every slot shows it."""
        ks = [self.free.get(timeout=SLOT_WAIT_S) for _ in range(SLOTS)]
        futs = []
        for k in ks:
            futs.append(Future())
            self.jobs[k].put((None, futs[-1]))
        res = [f.result(timeout=60) for f in futs]
        return {"sandbox": all(r["sandbox"] for r in res), "renderers": min(r["renderers"] for r in res)}

    def run(self, url):
        try:
            k = self.free.get(timeout=SLOT_WAIT_S)
        except queue.Empty:
            raise Unavailable() from None
        fut = Future()
        self.jobs[k].put((url, fut))
        return fut.result(timeout=PAGE_MS / 1000 * 2 + WAIT_MS / 1000 * 2 + 60)


def make_handler(pool, token):
    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):      # no access log
            pass

        def _send(self, status, obj):
            body = json.dumps(obj).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def _authed(self):
            h = self.headers.get("Authorization", "")
            return h.startswith("Bearer ") and hmac.compare_digest(h[7:], token)

        def do_GET(self):
            if self.path == "/healthz":
                return self._send(200, {"ok": True, "ready": all(e.is_set() for e in pool.ready)})
            if self.path == "/sandbox" and self._authed():
                return self._send(200, pool.probe())
            self._send(404, {"error": "not_found"})

        def do_POST(self):
            try:
                if self.path != "/capture" or not self._authed():
                    return self._send(401 if self.path == "/capture" else 404, {"error": "unauthorised"})
                n = int(self.headers.get("Content-Length", "0"))
                if n < 0:
                    return self._send(400, {"error": "bad_request"})
                if n > BODY_CAP:
                    return self._send(413, {"error": "too_large"})
                obj = json.loads(self.rfile.read(n))
                url = obj.get("url") if isinstance(obj, dict) else None
                if not isinstance(url, str) or urlsplit(url).scheme not in ("http", "https"):      # http and https only
                    return self._send(400, {"error": "bad_request"})
                self._send(200, pool.run(url))
            except Unavailable:
                self._send(503, {"error": "capture_unavailable"})
            except Exception as e:      # class name only
                _say("request failed: %s" % type(e).__name__)
                self._send(500, {"error": "internal"})
    return H


class Server(ThreadingHTTPServer):
    daemon_threads = True

    def handle_error(self, request, client_address):
        _say("connection error: %s" % type(sys.exc_info()[1]).__name__)


def main():
    sys.excepthook = lambda t, v, tb: _say("unhandled %s" % t.__name__)
    threading.excepthook = lambda a: _say("unhandled %s" % a.exc_type.__name__)
    try:
        import resource
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))      # no core dumps
    except Exception:
        pass
    token = open(TOKEN_FILE).read().strip()
    pool = Pool()
    for e in pool.ready:      # the worker refuses to start when a slot cannot show an active sandbox
        for _ in range(180):
            if e.is_set() or pool.failed.is_set():
                break
            time.sleep(1)
        if not e.is_set():
            _say("sandbox not active or browser failed to start")
            sys.exit(3)
    Server((BIND, PORT), make_handler(pool, token)).serve_forever()


if __name__ == "__main__":
    main()
