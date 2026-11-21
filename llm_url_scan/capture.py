"""Capture client interface: the real client talks to the isolated browser worker behind the egress proxy; a stub serves the tests.

capture(url) returns a dict:
  readable            bool
  unreadable_reason   None | gone | site_blocked | proxy_refused | other
  unreadable_detail   None | one of logs.DETAILS      range_class  None | one of logs.RANGE_CLASSES
  sections            {"final_url", "page_meta", "page_text", "page_forms"}   (the five sections minus the input address; held in memory only)
  capture_ms, tries, redirects, forms (int)           http_status_class  None | 2xx..5xx
It raises CaptureUnavailable when the worker or proxy is down (our capacity, not a page property: 503, never a hold).
"""


import asyncio
import json
import urllib.request
from pathlib import Path


class CaptureUnavailable(Exception):
    """The capture worker or proxy cannot take the call."""


class StubCapture:
    """Test double: `results` maps an address to a capture dict, or to an Exception instance to raise."""

    def __init__(self, results):
        self.results, self.calls = results, []

    async def capture(self, url):
        self.calls.append(url)
        r = self.results[url]
        if isinstance(r, Exception):
            raise r
        return r


class WorkerClient:
    """The real client: POST the address to the capture worker on api-net with the worker token. Any transport failure, non-200 answer or
    malformed body is CaptureUnavailable (503), never a hold. No message of the failure is kept."""

    def __init__(self, url, token, timeout=190):
        self.url, self.token, self.timeout = url.rstrip("/"), token, timeout

    def _post(self, url):
        req = urllib.request.Request(self.url + "/capture", data=json.dumps({"url": url}).encode(), method="POST",
                                     headers={"Authorization": "Bearer " + self.token, "Content-Type": "application/json"})
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))      # never an environment proxy
        with opener.open(req, timeout=self.timeout) as r:
            return json.loads(r.read(4 * 1024 * 1024))

    async def capture(self, url):
        try:
            d = await asyncio.to_thread(self._post, url)
        except Exception:
            raise CaptureUnavailable() from None
        if not (isinstance(d, dict) and isinstance(d.get("readable"), bool) and isinstance(d.get("sections"), dict)
                and all(isinstance(v, str) for v in d["sections"].values())):
            raise CaptureUnavailable()
        return d


def make_client(cfg):
    return WorkerClient(cfg.worker_url, Path(cfg.worker_token_file).read_text().strip())
