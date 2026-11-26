"""The scan pipeline. Advisory only: nothing acts on the answer."""
import asyncio
import time
from collections import deque
from datetime import datetime, timezone

from . import __version__
from .capture import CaptureUnavailable
from .decide import SHORT_CHARS, decide, routed_because, state_of
from .judge import (HAIKU, INPUT_UPPER, PROMPT_SHA, SONNET, build_message, call_model, input_bound, model_sections, reservation)
from .ledger import SpendCap
from .pagefacts import could_not_scan_reason, shop_signal
from .patterns import P05, P12, P13, P15
from .store import hid_of
from .urlcheck import validate_url

DEADLINE_S, QUEUE_MAX, QUEUE_WAIT_S, CAPTURE_SLOTS, RATE_PER_MIN = 200, 10, 30, 2, 30
MODELS = (HAIKU, SONNET)


class Refusal(Exception):
    """An error answer with no decision. Nothing is a hold."""

    def __init__(self, code, status, retry_after=None):
        super().__init__(code)
        self.code, self.status, self.retry_after = code, status, retry_after


def _mfields(p, rec):
    """Log fields of one model record (enums, ints, numbers only)."""
    if rec is None:
        return {}
    u = rec.get("usage") or {}
    return {p + "model": rec.get("model") or (HAIKU if p == "h_" else SONNET), p + "outcome": rec["outcome"], p + "reason": rec["reason"],
            p + "verdict": rec.get("verdict"), p + "state": state_of(rec), p + "rules": rec.get("rules"), p + "brand_present": rec.get("brand_present"),
            p + "injection": rec.get("injection_text"), p + "quotes_total": rec.get("quotes_total"), p + "quotes_matched": rec.get("quotes_matched"),
            p + "rule_without_quote": rec.get("rule_without_quote"), p + "stop_reason": rec.get("stop_reason"), p + "in_tok": u.get("input_tokens"),
            p + "out_tok": u.get("output_tokens"), p + "cost_usd": rec.get("cost_usd"), p + "latency_s": rec.get("latency_s"), p + "request_id": rec.get("request_id")}


def _view(rec):
    """What an answer says about one model run: no quote, brand string or page text."""
    if rec is None:
        return None
    return {"state": state_of(rec), "outcome": rec["outcome"], "reason": rec["reason"], "verdict": rec.get("verdict"), "rules": rec.get("rules"),
            "brand_present": rec.get("brand_present"), "injection_text": rec.get("injection_text")}


class Service:
    def __init__(self, *, client, webrisk, capture, ledger, log, store, salt, salt_ver, prompt, could_not_scan=True, shop_routing=False,
                 clock=lambda: datetime.now(timezone.utc), sleep=time.sleep):
        self.could_not_scan, self.shop_routing = could_not_scan, shop_routing
        self.client, self.webrisk, self.capture, self.ledger, self.log, self.store = client, webrisk, capture, ledger, log, store
        self.salt, self.salt_ver, self.prompt, self.clock, self.sleep = salt, salt_ver, prompt, clock, sleep
        self._sem, self._waiting, self._hits, self._first_call, self.served = asyncio.Semaphore(CAPTURE_SLOTS), 0, {}, True, 0
        self.store_errors = 0

    # ---------------------------------------------------------------- admission
    def _rate(self, caller):
        q, now = self._hits.setdefault(caller, deque()), time.monotonic()
        while q and now - q[0] > 60:
            q.popleft()
        if len(q) >= RATE_PER_MIN:
            raise Refusal("rate_limited", 429, retry_after=int(60 - (now - q[0])) + 1)
        q.append(now)

    def _admit(self, bound=INPUT_UPPER):
        if self.ledger.open_kinds():
            raise Refusal("paused", 503)
        try:
            return self.ledger.reserve(reservation(MODELS, bound))
        except SpendCap:
            raise Refusal("spend_cap", 503) from None

    async def _capture(self, url):
        if self._waiting >= QUEUE_MAX:
            raise Refusal("busy", 429, retry_after=QUEUE_WAIT_S)
        self._waiting += 1
        try:
            await asyncio.wait_for(self._sem.acquire(), QUEUE_WAIT_S)
        except asyncio.TimeoutError:
            raise Refusal("busy", 429, retry_after=QUEUE_WAIT_S) from None
        finally:
            self._waiting -= 1
        try:
            return await self.capture.capture(url)
        except CaptureUnavailable:
            raise Refusal("capture_unavailable", 503) from None
        finally:
            self._sem.release()

    # ---------------------------------------------------------------- judging
    async def _model(self, model, msg, quote_page, empty):
        rec = await asyncio.to_thread(call_model, self.client, model, self.prompt, msg, quote_page, empty, self.sleep)
        first, self._first_call = self._first_call, False
        kind = rec.get("stop_kind") or ("shape400" if first and rec.get("http_status") == 400 and rec.get("reason") != "policy_word_400" else None)
        if kind:      # account-level or request-shape failure: stop, no decision
            self.ledger.open_breaker(kind)
            self.log.write("breaker", kind=kind, state="open")
            raise Refusal("paused", 503)
        return rec

    async def _judge(self, url, cap, rid):
        """-> dict with h, s, d (decision), info, cost. An unreadable page or a page with nothing to judge is could_not_scan and no model runs."""
        stop = "could_not_scan" if self.could_not_scan else "hold"
        if not cap["readable"]:
            return {"h": None, "s": None, "info": None, "cost": 0.0,
                    "d": {"decision": stop, "reason": "unreadable_" + cap["unreadable_reason"], "d1a_state": "UNREAD", "routed_because": None}}
        msg, info, quote_page = build_message(model_sections(url, cap["sections"]))
        why = could_not_scan_reason(cap["sections"]) if self.could_not_scan else None
        if why:      # read, but nothing to judge: no model runs, and the answer is never a pass
            return {"h": None, "s": None, "info": info, "cost": 0.0, "d": {"decision": "could_not_scan", "reason": why, "d1a_state": "UNREAD", "routed_because": None}}
        bound = input_bound(self.prompt, msg)
        if bound > INPUT_UPPER:
            try:
                self.ledger.topup(rid, reservation(MODELS, bound))
            except SpendCap:
                self.ledger.settle(rid, 0.0)      # no model was called
                raise Refusal("spend_cap", 503) from None
        h = await self._model(HAIKU, msg, quote_page, info["empty_page"])
        short = info["text_chars"] <= SHORT_CHARS
        shop = self.shop_routing and shop_signal(cap["sections"])
        s = await self._model(SONNET, msg, quote_page, info["empty_page"]) if routed_because(h, short, shop) else None
        return {"h": h, "s": s, "info": info, "d": decide(h, s, short, shop), "cost": round(h["cost_usd"] + (s["cost_usd"] if s else 0.0), 6)}

    def _record(self, res):
        """Rolling statistics for the breakers; logs a breaker event for each one opened."""
        recs = [r for r in (res["h"], res["s"]) if r]
        if not recs:
            return
        for k in self.ledger.record_scan(res["cost"], any(r["reason"] == "refusal" for r in recs), any(r["reason"] == "parse_fail" for r in recs),
                                         any(r["reason"] == "max_tokens" for r in recs), any(r["outcome"] == "ERROR" for r in recs)):
            self.log.write("breaker", kind=k, state="open")

    # ---------------------------------------------------------------- the two entry points
    async def scan(self, url, caller):
        """-> the answer dict (no id). Raises UrlRejected or Refusal."""
        validate_url(url)
        self._rate(caller)
        rid = self._admit()
        try:
            return await asyncio.wait_for(self._scan(url, caller, rid), DEADLINE_S)
        except asyncio.TimeoutError:
            raise Refusal("deadline", 504) from None
        finally:
            self.ledger.settle(rid)      # no-op when already settled; an unfinished call keeps its full reservation

    async def _scan(self, url, caller, rid):
        t0, now = time.monotonic(), self.clock()
        hid = hid_of(self.salt, url)
        try:
            cap, wr = await asyncio.gather(self._capture(url), asyncio.to_thread(self.webrisk.check, url))
        except Refusal:
            self.ledger.settle(rid, 0.0)
            raise
        res = await self._judge(url, cap, rid)
        self.ledger.settle(rid, res["cost"])
        self._record(res)
        d, h, s, info = res["d"], res["h"], res["s"], res["info"] or {}
        sec = cap.get("sections") or {}
        flags = {"p05": int(P05(sec)), "p12": int(P12(sec)), "p13": int(P13(sec)), "p15": P15(info["text_chars"])} if info else {}
        latency_ms = int((time.monotonic() - t0) * 1000)
        self.log.write("scan", hid=hid, salt_ver=self.salt_ver, caller=caller, decision=d["decision"], reason=d["reason"], readable=cap["readable"],
                       unreadable_reason=cap.get("unreadable_reason"), unreadable_detail=cap.get("unreadable_detail"), range_class=cap.get("range_class"),
                       capture_ms=cap.get("capture_ms"), tries=cap.get("tries"), redirects=cap.get("redirects"), http_status_class=cap.get("http_status_class"),
                       text_chars=info.get("text_chars"), truncated=info.get("truncated"), short=(info["text_chars"] <= SHORT_CHARS) if info else None,
                       empty_page=info.get("empty_page"), forms=cap.get("forms"), s_routed_because=d["routed_because"], d1a_state=d["d1a_state"],
                       wr_d0=wr, wr_d0_date=now.strftime("%Y-%m-%d"), cost_usd=res["cost"], latency_ms=latency_ms, prompt_sha256=PROMPT_SHA,
                       service_version=__version__, **flags, **_mfields("h_", h), **_mfields("s_", s))
        try:      # the address waits, sealed, for the day-7 and the 6 h recheck
            self.store.insert(hid, self.salt_ver, url, now, r6=d["decision"] == "could_not_scan" or d["reason"].startswith("unreadable_") or d["reason"] == "hold_sonnet_cannot_tell")
        except Exception:
            self.store_errors += 1
        self.served += 1
        return {"decision": d["decision"], "reason": d["reason"], "advisory": True, "readable": cap["readable"],
                "unreadable_reason": cap.get("unreadable_reason"), "models_run": [m for m, r in ((HAIKU, h), (SONNET, s)) if r],
                "haiku": _view(h), "sonnet": _view(s), "d1a": {"state": d["d1a_state"], "routed_because": d["routed_because"]}, "web_risk_d0": wr,
                "text_chars": info.get("text_chars", 0), "short": bool(info) and info["text_chars"] <= SHORT_CHARS, "cost_usd": res["cost"],
                "latency_ms": latency_ms, "prompt_sha256": PROMPT_SHA, "service_version": __version__}

    async def recheck6(self, url, hid, salt_ver):
        """Internal path for the scheduler: one more capture and D1a judgement about 6 h after the first scan. Logged only; the first
        decision stands. Skipped (and logged so) when a cap or a breaker stops it."""
        skipped = dict(hid=hid, salt_ver=salt_ver, r6_skipped=True)
        try:
            rid = self._admit()
        except Refusal:
            return self.log.write("recheck6", **skipped)
        try:
            cap = await asyncio.wait_for(self._capture(url), DEADLINE_S)
        except (Refusal, asyncio.TimeoutError):
            self.ledger.settle(rid, 0.0)
            return self.log.write("recheck6", **skipped)
        try:
            res = await asyncio.wait_for(self._judge(url, cap, rid), DEADLINE_S)
        except (Refusal, asyncio.TimeoutError):
            self.ledger.settle(rid)      # a model may have been billed: keep the full reservation
            return self.log.write("recheck6", **skipped)
        self.ledger.settle(rid, res["cost"])
        self._record(res)
        st = lambda r: state_of(r) if r else None      # noqa: E731
        return self.log.write("recheck6", hid=hid, salt_ver=salt_ver, r6_skipped=False, r6_readable=cap["readable"],
                              r6_unreadable_reason=cap.get("unreadable_reason"), r6_h_state=st(res["h"]), r6_s_state=st(res["s"]),
                              r6_d1a_state=res["d"]["d1a_state"], r6_cost_usd=res["cost"])

    def status(self):
        today, total = self.ledger.spent()
        return {"spend_today_usd": today, "spend_total_usd": total, "daily_cap_usd": self.ledger.daily_cap, "total_cap_usd": self.ledger.total_cap,
                "open_breakers": self.ledger.open_kinds(), "answered": self.served, "log_rejected": self.log.rejected, "store_errors": self.store_errors}
