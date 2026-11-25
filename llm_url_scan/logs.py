"""Counts-only log. One JSON line per event, allow-listed keys, enum / number / hash values only.
token_ok and check_text check that every token is a number, an id or a word of the closed vocabulary; check_line is the guard every line passes."""
import json
import math
import os
import re
import threading
from datetime import datetime, timezone

UNREAD_REASONS = ("gone", "site_blocked", "proxy_refused", "other")
DETAILS = ("deadline", "name_blocked", "numeric_host", "literal_blocked", "resolved_blocked", "port_not_allowed", "bad_request", "upgrade", "dns",
           "http_404", "http_410", "refused", "unreachable", "parked", "http_4xx", "bot_wall", "unclassified", "browser_crash")
RANGE_CLASSES = ("private", "loopback_or_unspecified", "link_local_or_metadata", "reserved_or_doc", "own_or_extra", "v6_other")
DECISION_REASONS = ("unreadable_gone", "unreadable_site_blocked", "unreadable_proxy_refused", "unreadable_other", "pass_haiku",
                    "pass_sonnet_confirmed_short", "pass_sonnet_overrode_hold", "pass_sonnet_resolved", "hold_sonnet_verdict",
                    "hold_sonnet_cannot_tell", "hold_sonnet_failed", "pass_sonnet_confirmed_shop", "page_empty", "page_error", "page_bot_wall", "page_parked")
STATES = ("PASS", "HOLD", "CANNOT", "UNREAD")
ROUTES = ("h_hold", "h_cannot", "h_failed", "short_pass", "shop_page")
WR_STATES = ("positive", "negative", "error", "not_checked")
MODELS = ("claude-haiku-5-5", "claude-sonnet-5-5")
OUTCOMES = ("PASS", "HOLD", "CAPTURE", "FAILED", "ERROR")
MODEL_REASONS = ("verdict", "refusal", "parse_fail", "quote_unmatched", "cannot_tell", "empty_page", "max_tokens", "pause_turn", "api_error",
                 "policy_word_400", "pause_exhausted")
VERDICT_VALUES = ("phishing", "suspicious", "benign", "cannot_tell")
STOP = ("end_turn", "max_tokens", "stop_sequence", "tool_use", "pause_turn", "refusal", "other")
ERROR_CODES = ("bad_request", "unauthorised", "too_large", "url_not_allowed", "busy", "rate_limited", "spend_cap", "paused",
               "capture_unavailable", "deadline", "internal", "not_found", "method_not_allowed")
BREAKER_KINDS = ("refusal_content", "parse_storm", "maxtok_storm", "meancost", "errors3", "credit", "auth", "shape400")

_HEX64, _TS = re.compile(r"[0-9a-f]{64}"), re.compile(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ")
_DATE, _CALLER = re.compile(r"\d{4}-\d\d-\d\d"), re.compile(r"[a-z0-9_-]{1,20}")
_REQID, _VER, _CLASS = re.compile(r"[A-Za-z0-9_-]{1,80}"), re.compile(r"[0-9.]{1,20}"), re.compile(r"[A-Za-z]{1,40}")


def E(*v):
    return ("enum", frozenset(v))


_N, _B, _H, _X = ("int",), ("bool",), ("hex",), ("num",)
_P = lambda rx: ("pat", rx)      # noqa: E731

_MODEL_FIELDS = {"model": E(*MODELS), "outcome": E(*OUTCOMES), "reason": E(*MODEL_REASONS), "verdict": E(*VERDICT_VALUES), "state": E("PASS", "HOLD", "CANNOT"),
                 "rules": ("rules",), "brand_present": _B, "injection": _B, "quotes_total": _N, "quotes_matched": _N, "rule_without_quote": _B,
                 "stop_reason": E(*STOP), "in_tok": _N, "out_tok": _N, "cost_usd": _X, "latency_s": _X, "request_id": _P(_REQID)}
_SCAN = {"hid": _H, "salt_ver": _N, "caller": _P(_CALLER), "decision": E("pass", "hold", "could_not_scan"), "reason": E(*DECISION_REASONS), "readable": _B,
         "unreadable_reason": E(*UNREAD_REASONS), "unreadable_detail": E(*DETAILS), "range_class": E(*RANGE_CLASSES), "capture_ms": _N, "tries": _N,
         "redirects": _N, "http_status_class": E("2xx", "3xx", "4xx", "5xx"), "text_chars": _N, "truncated": _B, "short": _B, "empty_page": _B,
         "forms": _N, "s_routed_because": E(*ROUTES), "d1a_state": E(*STATES), "p05": E(0, 1), "p12": E(0, 1), "p13": E(0, 1),
         "p15": E("under40", "thin", "longer"), "wr_d0": E(*WR_STATES), "wr_d0_date": _P(_DATE), "cost_usd": _X, "latency_ms": _N,
         "prompt_sha256": _H, "service_version": _P(_VER)}
for _p in ("h_", "s_"):
    _SCAN.update({_p + k: v for k, v in _MODEL_FIELDS.items()})
SPECS = {
    "scan": _SCAN,
    "recheck": {"hid": _H, "salt_ver": _N, "wr_d7": E("positive", "negative", "error", "missed_window", "missed_key"), "age_days": _N, "wr_attempts": _N},
    "recheck6": {"hid": _H, "salt_ver": _N, "r6_skipped": _B, "r6_readable": _B, "r6_unreadable_reason": E(*UNREAD_REASONS), "r6_h_state": E(*STATES),
                 "r6_s_state": E(*STATES), "r6_d1a_state": E(*STATES), "r6_cost_usd": _X},
    "refusal": {"caller": _P(_CALLER), "code": E(*ERROR_CODES), "exc": _P(_CLASS)},
    "breaker": {"kind": E(*BREAKER_KINDS), "state": E("open", "resumed")},
}
VOCAB = {str(v) for sp in SPECS.values() for t in sp.values() if t[0] == "enum" for v in t[1]} | set(SPECS)
_NUM = re.compile(r"-?\d+(\.\d+)?%?")
_HEXTOK = re.compile(r"[0-9a-f]{12}|[0-9a-f]{64}")


def token_ok(tok, vocab):
    """True for an integer, a decimal, a 12 or 64 hex id, a word of the closed vocabulary, or key=value of those."""
    t = tok.strip("[](),:;|")
    if not t:
        return True
    if "=" in t:
        k, _, v = t.partition("=")
        return k in vocab and token_ok(v, vocab)
    return bool(_NUM.fullmatch(t) or _HEXTOK.fullmatch(t) or t in vocab)


def check_text(text, vocab=VOCAB):
    """-> list of (line, token position) of tokens that fail. Used on report output too."""
    return [(i, j) for i, line in enumerate(text.splitlines(), 1) for j, tok in enumerate(re.split(r"\s+", line), 1) if not token_ok(tok, vocab)]


def _valid(spec, v):
    kind = spec[0]
    if kind == "enum":
        return (v in spec[1]) if not isinstance(v, bool) else False
    if kind == "int":
        return isinstance(v, int) and not isinstance(v, bool) and v >= 0
    if kind == "num":
        return isinstance(v, (int, float)) and not isinstance(v, bool) and math.isfinite(v) and v >= 0
    if kind == "bool":
        return isinstance(v, bool)
    if kind == "hex":
        return isinstance(v, str) and bool(_HEX64.fullmatch(v))
    if kind == "pat":
        return isinstance(v, str) and bool(spec[1].fullmatch(v))
    if kind == "rules":
        return isinstance(v, list) and all(isinstance(r, str) and re.fullmatch(r"R[1-9]", r) for r in v)
    return False


def check_line(line):
    """The leak guard for one log line: -> list of problems (key names only, never values). Empty = clean."""
    try:
        obj = json.loads(line)
    except ValueError:
        return ["not_json"]
    if not isinstance(obj, dict) or not _TS.fullmatch(str(obj.get("ts", ""))) or obj.get("event") not in SPECS:
        return ["bad_header"]
    spec, bad = SPECS[obj["event"]], []
    for k, v in obj.items():
        if k in ("ts", "event"):
            continue
        if k not in spec:
            bad.append("key:" + (k if re.fullmatch(r"[a-z0-9_]{1,40}", k) else "?"))
        elif v is not None and not _valid(spec[k], v):
            bad.append("value:" + k)
        elif isinstance(v, str) and spec[k][0] == "enum" and not token_ok(v, VOCAB):
            bad.append("token:" + k)
    return bad


class LogWriter:
    """Append-only, one fsync per line, file scan-YYYY-MM.jsonl, mode 0600. A line that fails the guard is dropped and counted (no content)."""

    def __init__(self, data_dir, clock=lambda: datetime.now(timezone.utc)):
        self.dir, self.clock, self.rejected, self._lock = str(data_dir), clock, 0, threading.Lock()

    def write(self, event, **fields):
        now = self.clock()
        rec = {"ts": now.strftime("%Y-%m-%dT%H:%M:%SZ"), "event": event}
        rec.update({k: v for k, v in fields.items() if v is not None})
        line = json.dumps(rec, separators=(",", ":"), ensure_ascii=True)
        if check_line(line):
            self.rejected += 1
            return False
        with self._lock:
            fd = os.open(os.path.join(self.dir, "scan-%s.jsonl" % now.strftime("%Y-%m")), os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
            try:
                os.write(fd, (line + "\n").encode("ascii"))
                os.fsync(fd)
            finally:
                os.close(fd)
        return True
