"""Judge: message builder, answer parser, outcome derivation and one model call.

Never stores or returns page text, quotes, brand strings or error messages.
"""
import hashlib
import json
import re
import time
import unicodedata
from pathlib import Path
from urllib.parse import urlsplit

PROMPT_PATH = Path(__file__).parent / "prompts" / "prompt-v3.md"
PROMPT_SHA = "1c7b2bbe7e1e8c296f7b0db4dc32b51a17dfa6ea46b67592d0c3962a865c49d7"
ANTHROPIC_BASE = "https://api.anthropic.com"
HAIKU, SONNET = "claude-haiku-5-5", "claude-sonnet-5-5"
PRICES = {HAIKU: (0.10, 0.50), SONNET: (2.00, 10.00)}   # USD per million tokens, in / out
INPUT_UPPER, MAX_TOKENS = 8500, 4096
TIMEOUT = {HAIKU: 45, SONNET: 60}
VERDICTS = {"phishing", "suspicious", "benign", "cannot_tell"}
STOP_REASONS = ("end_turn", "max_tokens", "stop_sequence", "tool_use", "pause_turn", "refusal")
SIGNAL_WORDS = ("quota", "terms", "waitlist", "access", "filter", "policy", "suspend", "violation", "moderation")
BILLING_WORDS = ("billing", "credit", "balance")
KEY_PREFIX = "sk-ant" + "-"


def load_prompt():
    """The frozen system prompt; the service refuses to start if the bytes differ."""
    raw = PROMPT_PATH.read_bytes()
    if hashlib.sha256(raw).hexdigest() != PROMPT_SHA:
        raise RuntimeError("prompt hash mismatch")
    return raw.decode("utf-8")


def build_client(key):
    """Fixed endpoint, no SDK retries, no environment trust (no proxy or certificate-bundle variable is read), no redirect following.
    The SDK (2.x) uses httpx2, not httpx."""
    import anthropic
    import httpx2
    return anthropic.Anthropic(api_key=key, base_url=ANTHROPIC_BASE, max_retries=0,
                               http_client=httpx2.Client(trust_env=False, follow_redirects=False))


# ---------------------------------------------------------------- the judge message assembly (changing it changes what the model sees)
TEXT_CAP, URL_CAP, META_CAP, TITLE_CAP, TOTAL_CHARS, FORMS_CAP, TAIL_KEEP = 7000, 600, 600, 200, 12000, 3800, 1000
URL_ONLY_RULES = {"R2", "R5", "R7", "R8", "R9"}
_TAG_RE = re.compile(r"<(/?)(url|final_url|page_meta|page_text|page_forms)\b", re.I)


def norm(s):
    return re.sub(r"\s+", " ", s).strip().lower()


def parse_answer(text):
    """First {...} span of the final text; strict schema check. -> dict or None."""
    i, j = text.find("{"), text.rfind("}")
    if i < 0 or j <= i:
        return None
    try:
        a = json.loads(text[i:j + 1])
    except ValueError:
        return None
    if not isinstance(a, dict) or a.get("verdict") not in VERDICTS:
        return None
    rules, brand, quotes, inj = a.get("rules"), a.get("brand"), a.get("quotes"), a.get("injection_text")
    if not (isinstance(rules, list) and all(isinstance(r, str) and re.fullmatch(r"R[1-9]", r) for r in rules)):
        return None
    if not (brand is None or isinstance(brand, str)):
        return None
    if not (isinstance(quotes, list) and len(quotes) <= 3 and all(isinstance(q, str) for q in quotes)):
        return None
    if not isinstance(inj, bool):
        return None
    return {"verdict": a["verdict"], "rules": rules, "brand": brand, "quotes": quotes, "injection_text": inj}


def derive_outcome(stop_reason, answer, quotes_ok, empty_page=False):
    """Order: refusal, pause, parse fail, cannot_tell, quote check, empty-page check (the tool-result branches are gone: no tool)."""
    if stop_reason == "refusal":
        return "HOLD", "refusal"
    if stop_reason == "pause_turn":
        return "CAPTURE", "pause_exhausted"
    if answer is None:
        return "HOLD", "parse_fail"
    if answer["verdict"] == "cannot_tell":
        return "CAPTURE", "cannot_tell"
    if not quotes_ok:
        return "HOLD", "quote_unmatched"
    if empty_page and answer["verdict"] == "benign":
        return "CAPTURE", "empty_page"
    return ("PASS" if answer["verdict"] == "benign" else "HOLD"), "verdict"


def _fold(s):
    """NFKC with invisible format characters removed, plus the index of each folded character in the original."""
    out, idx = [], []
    for i, ch in enumerate(s):
        for c in unicodedata.normalize("NFKC", ch):
            if unicodedata.category(c) != "Cf":
                out.append(c)
                idx.append(i)
    return "".join(out), idx


def neutralise(s):
    """A page must not close or open one of our sections: '</page_text' becomes '<\\/page_text'.
    Also near-miss forms (full-width letters, invisible characters inside the name); other text is left unchanged."""
    if s.isascii():
        return _TAG_RE.sub(lambda m: "<\\" + m.group(1) + m.group(2), s)
    folded, idx = _fold(s)
    for m in reversed(list(_TAG_RE.finditer(folded))):
        s = s[:idx[m.start()]] + "<\\" + m.group(1) + m.group(2) + s[idx[m.end() - 1] + 1:]
    return s


def cut_middle(s, n):
    if len(s) <= n:
        return s
    k = n - 5
    head = (k + 1) // 2
    return s[:head] + "[...]" + s[len(s) - (k - head):]


def cap_text(text, cap):
    if len(text) <= cap:
        return text, False
    tail = min(TAIL_KEEP, cap // 7)
    marker_len = len("[truncated] (%d characters omitted)" % len(text))
    head = max(0, cap - tail - marker_len - 2)
    marker = "[truncated] (%d characters omitted)" % (len(text) - head - tail)
    return text[:head] + "\n" + marker + "\n" + text[len(text) - tail:], True


def shrink_forms(forms, cap):
    if len(forms) <= cap:
        return forms, False
    for pat in (r' hint="[^"]*"', r" id=\S+", r" autocomplete=\S+"):
        forms = re.sub(pat, "", forms)
        if len(forms) <= cap:
            return forms, True
    lines = forms.split("\n")
    keep_btn = [l for l in lines if l.lstrip().lower().startswith("buttons")]
    others = [l for l in lines if l not in keep_btn]
    budget = cap - sum(len(l) + 1 for l in keep_btn) - 20
    out, used = [], 0
    for l in others:
        if used + len(l) + 1 > budget:
            break
        out.append(l)
        used += len(l) + 1
    res = "\n".join(out + ["+%d more" % (len(others) - len(out))] + keep_btn)
    return res[:cap], True


def _set_truncated(meta, flag):
    line = "truncated: " + ("yes" if flag else "no")
    if re.search(r"(?m)^truncated:.*$", meta):
        return re.sub(r"(?m)^truncated:.*$", line, meta)
    return (meta + "\n" if meta else "") + line


def _render(url, final, meta, text, forms):
    return ("<url>%s</url>\n<final_url>%s</final_url>\n<page_meta>\n%s\n</page_meta>\n<page_text>\n%s\n</page_text>\n"
            "<page_forms>\n%s\n</page_forms>" % (url, final, meta, text, forms))


def build_message(sec, cap=TOTAL_CHARS):
    """sec: dict of the five sections. -> (user message of at most `cap` characters, info dict, page text for the quote check)."""
    url = neutralise(cut_middle(sec.get("url", "").strip(), URL_CAP))
    final = neutralise(cut_middle(sec.get("final_url", "").strip() or "none", URL_CAP))
    meta = neutralise(sec.get("page_meta", "").strip())
    meta = re.sub(r"(?m)^(title:)[ \t]*(.*)$", lambda m: m.group(1) + " " + m.group(2)[:TITLE_CAP], meta)
    meta = meta[:META_CAP]
    forms, f_cut = shrink_forms(neutralise(sec.get("page_forms", "").strip()), FORMS_CAP)
    text = neutralise(sec.get("page_text", "").strip())
    meta_worst = _set_truncated(meta, True)
    budget = max(500, min(TEXT_CAP, cap - len(_render(url, final, meta_worst, "", forms))))
    text, t_cut = cap_text(text, budget)
    was_cut = f_cut or t_cut or bool(re.search(r"(?mi)^truncated:[ \t]*yes", meta))
    meta = _set_truncated(meta, was_cut)
    msg = _render(url, final, meta, text, forms)
    has_forms = bool(re.search(r"(?mi)^\s*(form \d+|field:|loose fields|buttons:)", forms))
    info = {"message_chars": len(msg), "text_chars": len(text), "truncated": was_cut, "empty_page": not text.strip() and not has_forms}
    return msg, info, "\n".join((text, forms, meta))


# ---------------------------------------------------------------- end of the message assembly

def cut_query(u):
    """The model sees scheme, host and path plus the query length, never the query. Fragment dropped."""
    u = u.strip()
    if "://" not in u:
        return u
    try:
        p = urlsplit(u)
    except ValueError:
        return "none"
    return "%s://%s%s" % (p.scheme, p.netloc, p.path) + ("?[query %d chars]" % len(p.query) if p.query else "")


def model_sections(url, sections):
    """The five sections as the model gets them: both addresses with the query cut."""
    sec = dict(sections)
    sec["url"] = cut_query(url)
    sec["final_url"] = cut_query(sections.get("final_url", ""))
    return sec


def usage_ints(u):
    """Only plain integer counts are kept."""
    return {k: v for k, v in (u or {}).items() if isinstance(k, str) and re.fullmatch(r"[a-z_]{1,50}", k) and isinstance(v, int)
            and not isinstance(v, bool) and v >= 0}


def usage_ok(u):
    return u.get("input_tokens", 0) >= 1 and "output_tokens" in u and all(v <= u["output_tokens"] for k, v in u.items() if "thinking" in k)


def cost_of(usage, model):
    pin, pout = PRICES[model][0] / 1e6, PRICES[model][1] / 1e6
    u = lambda k: usage.get(k) or 0
    return (u("input_tokens") * pin + u("cache_creation_input_tokens") * pin * 1.25 + u("cache_read_input_tokens") * pin * 0.1 + u("output_tokens") * pout)


def upper_cost(model, input_tokens=INPUT_UPPER):
    """Worst case of one call: input_tokens at the input price plus max_tokens of output. Also what a call with no response is charged."""
    pin, pout = PRICES[model]
    return round(input_tokens * pin / 1e6 + MAX_TOKENS * pout / 1e6, 6)


def input_bound(system, message):
    """Tokens never exceed bytes, so prompt bytes plus message bytes bounds the input; never below the 8,500 plan bound."""
    return max(INPUT_UPPER, len(system.encode("utf-8")) + len(message.encode("utf-8")))


def reservation(models, bound=INPUT_UPPER, retries=1):
    """Spend to reserve before calling: (1 + retries) x the per-model upper bound."""
    return round((1 + retries) * sum(upper_cost(m, bound) for m in models), 6)


def _safe_id(x):
    return x if isinstance(x, str) and re.fullmatch(r"[A-Za-z0-9_-]{1,80}", x) else None


def to_dict(r):
    return r.model_dump(exclude_none=True, mode="json") if hasattr(r, "model_dump") else r


def _attempt(client, model, system, content, quote_page, empty_page):
    """One request (no tool, no thinking field). Returns a record: no quote, page text, brand string or error message."""
    kw = dict(model=model, max_tokens=MAX_TOKENS, system=system, messages=[{"role": "user", "content": content}],
              output_config={"effort": "high"}, timeout=TIMEOUT[model])
    t0 = time.time()
    try:
        resp = to_dict(client.messages.create(**kw))
    except Exception as e:      # class name, status and request id only; the message is read in memory for stop signals and dropped
        status = getattr(e, "status_code", None)
        status = status if isinstance(status, int) else None
        msg = str(e).lower()
        name = type(e).__name__
        rec = {"outcome": "ERROR", "reason": "api_error", "error": name if re.fullmatch(r"[A-Za-z]{1,40}", name) else "Error", "http_status": status,
               "request_id": _safe_id(getattr(e, "request_id", None)), "usage": {}, "latency_s": round(time.time() - t0, 2), "cost_usd": 0.0}
        hdr = getattr(getattr(e, "response", None), "headers", None)
        try:
            rec["retry_after"] = float(hdr.get("retry-after")) if hdr is not None and hdr.get("retry-after") else None
        except (TypeError, ValueError, AttributeError):
            rec["retry_after"] = None
        if status is None or status < 400:      # no response, or a 2xx/3xx the SDK rejected: the call may have been billed
            rec["cost_usd"] = upper_cost(model)
        if status == 402 or (status == 400 and any(w in msg for w in BILLING_WORDS)):
            rec["stop_kind"] = "credit"
        elif status in (401, 403) or name in ("AuthenticationError", "PermissionDeniedError"):
            rec["stop_kind"] = "auth"
        elif status == 400 and any(w in msg for w in SIGNAL_WORDS):
            rec["reason"] = "policy_word_400"
        return rec
    if not isinstance(resp, dict):
        resp = {}
    sr = resp.get("stop_reason")
    usage = usage_ints(resp.get("usage"))
    rec = {"model": model, "request_id": _safe_id(resp.get("id")), "stop_reason": sr if sr in STOP_REASONS else "other", "usage": usage,
           "latency_s": round(time.time() - t0, 2), "cost_usd": round(cost_of(usage, model), 6)}
    if not usage_ok(usage):      # missing or odd usage is never free
        rec["cost_usd"] = upper_cost(model)
    final = "".join(b.get("text", "") for b in (resp.get("content") or []) if isinstance(b, dict) and b.get("type") == "text" and isinstance(b.get("text"), str))
    if sr in ("max_tokens", "pause_turn"):
        rec["outcome"], rec["reason"], rec["verdict"] = "FAILED", sr, None
        return rec
    ans = parse_answer(final) if sr != "refusal" else None
    quotes_ok = True
    if ans:
        p = norm(quote_page)
        matched = [norm(q) in p for q in ans["quotes"]]
        quotes_ok = all(matched)
        rec["rules"], rec["brand_present"], rec["injection_text"] = ans["rules"], ans["brand"] is not None, ans["injection_text"]
        rec["quotes_total"], rec["quotes_matched"] = len(matched), sum(matched)
        rec["rule_without_quote"] = bool(not ans["quotes"] and any(r not in URL_ONLY_RULES for r in ans["rules"]))
    rec["verdict"] = ans["verdict"] if ans else None
    rec["outcome"], rec["reason"] = derive_outcome(sr, ans, quotes_ok, empty_page)
    return rec


def _retryable(rec):
    s = rec.get("http_status")
    return rec["outcome"] == "ERROR" and not rec.get("stop_kind") and (s is None or s in (408, 409, 429) or s >= 500)


def call_model(client, model, system, content, quote_page, empty_page, sleep=time.sleep):
    """One model call with at most one retry (timeout, connection error, 408, 409, 429, 5xx) after 2 s or retry-after up to 10 s.
    Cost is the sum over attempts, so the retry stays inside the (1 + retries) reservation."""
    rec = _attempt(client, model, system, content, quote_page, empty_page)
    cost, attempts = rec["cost_usd"], 1
    if _retryable(rec):
        sleep(min(rec.get("retry_after") or 2.0, 10.0))
        rec = _attempt(client, model, system, content, quote_page, empty_page)
        cost, attempts = round(cost + rec["cost_usd"], 6), 2
    rec["cost_usd"], rec["attempts"] = cost, attempts
    rec.pop("retry_after", None)
    return rec
