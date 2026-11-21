"""Shared fixtures. Every address, host, brand and page text here is made up (reserved .example names); nothing touches the network."""
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from llm_url_scan.capture import StubCapture   # noqa: E402
from llm_url_scan.cli import build_service     # noqa: E402
from llm_url_scan.config import Config         # noqa: E402
from llm_url_scan.keys import init_secrets, load_callers, load_private_key  # noqa: E402

ADDR = "https://login.brandx-secure.example/account/verify?token=Zq81vKQ"
HOST = "login.brandx-secure.example"
MARKER = "ZEBRAQUILL-9931"          # made-up page text marker
BRAND = "Brandx Holdings"
LONG_TEXT = ("Welcome to the made-up page. " + MARKER + " ") * 60      # well over 1,000 characters
SHORT_TEXT = "A tiny page. " + MARKER


def answer(verdict="benign", quotes=(), rules=(), inj=False, brand=None):
    return json.dumps({"verdict": verdict, "rules": list(rules), "brand": brand, "quotes": list(quotes), "injection_text": inj})


def resp(text, stop="end_turn", inp=2000, out=100):
    return {"id": "msg_test01", "stop_reason": stop, "usage": {"input_tokens": inp, "output_tokens": out}, "content": [{"type": "text", "text": text}]}


class FakeClient:
    """Mocks the Anthropic SDK at the client boundary: client.messages.create(**kw). `script[model]` is a list of dicts or exceptions."""

    def __init__(self, haiku=(), sonnet=()):
        self.script = {"claude-haiku-5-5": list(haiku), "claude-sonnet-5-5": list(sonnet)}
        self.calls = []
        self.messages = self

    def create(self, **kw):
        self.calls.append(kw)
        item = self.script[kw["model"]].pop(0)
        if isinstance(item, Exception):
            raise item
        return item

    def models_called(self):
        return [c["model"] for c in self.calls]


class FakeWebRisk:
    def __init__(self, state="negative"):
        self.state, self.calls = state, []

    def check(self, url):
        self.calls.append(url)
        if isinstance(self.state, Exception):
            raise self.state
        return self.state


def page(text=LONG_TEXT, forms="", final=ADDR, meta="title: Made up page"):
    return {"readable": True, "unreadable_reason": None, "sections": {"final_url": final, "page_meta": meta, "page_text": text, "page_forms": forms},
            "capture_ms": 31000, "tries": 1, "redirects": 0, "forms": 0, "http_status_class": "2xx"}


def unreadable(reason, detail=None, range_class=None):
    return {"readable": False, "unreadable_reason": reason, "unreadable_detail": detail, "range_class": range_class, "sections": {}, "capture_ms": 1200,
            "tries": 1, "redirects": 0, "forms": 0, "http_status_class": None}


class Stack:
    pass


@pytest.fixture
def make(tmp_path):
    """make(client=..., capture=..., wr=..., **cfg) -> Stack with .svc .cfg .callers .token .log_text()"""
    def _make(client=None, capture=None, wr="negative", sleep=lambda s: None, sub="data", **cfg_kw):
        cfg = Config(data_dir=tmp_path / sub, **cfg_kw)
        init_secrets(cfg.data_dir)
        st = Stack()
        st.cfg, st.client, st.capture, st.wr = cfg, client or FakeClient(), capture or StubCapture({ADDR: page()}), FakeWebRisk(wr)
        st.svc = build_service(cfg, client=st.client, webrisk=st.wr, capture=st.capture, sleep=sleep)
        st.callers = load_callers(cfg.data_dir)
        st.token = (cfg.data_dir / "secrets" / "caller_token_owner").read_text()
        st.headers = {"Authorization": "Bearer " + st.token}
        st.private = load_private_key(cfg.data_dir)
        st.log_text = lambda: "".join(p.read_text() for p in sorted(cfg.data_dir.glob("scan-*.jsonl")))
        st.log_events = lambda: [json.loads(l) for l in st.log_text().splitlines()]
        return st
    return _make
