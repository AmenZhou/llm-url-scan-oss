"""The D1a routing rule: Haiku judges every readable page; Sonnet re-judges when Haiku holds, cannot tell or fails, or passes a short page."""

SHORT_CHARS = 1000      # a page with at most this many characters of text counts as short


def state_of(rec):
    """PASS | HOLD | CANNOT from a model record (CANNOT = CAPTURE outcome or a failed call)."""
    return {"PASS": "PASS", "HOLD": "HOLD"}.get(rec["outcome"], "CANNOT")


def routed_because(h, short):
    """Why Sonnet runs, or None. D1a: Sonnet when Haiku holds, cannot decide, or passes with at most 1,000 characters of text."""
    st = state_of(h)
    if st == "HOLD":
        return "h_hold"
    if st == "CANNOT":
        return "h_failed" if h["outcome"] in ("FAILED", "ERROR") else "h_cannot"
    return "short_pass" if short else None


def decide(h, s, short):
    """h, s: model records (s None when not routed); short: text_chars <= 1000. -> {decision, reason, d1a_state, routed_because}.
    An unreadable page is held by the caller before any model runs."""
    route = routed_because(h, short)
    if route is None:
        return {"decision": "pass", "reason": "pass_haiku", "d1a_state": "PASS", "routed_because": None}
    st = state_of(s)
    if st == "PASS":
        reason = {"short_pass": "pass_sonnet_confirmed_short", "h_hold": "pass_sonnet_overrode_hold"}.get(route, "pass_sonnet_resolved")
        return {"decision": "pass", "reason": reason, "d1a_state": "PASS", "routed_because": route}
    if st == "HOLD":
        return {"decision": "hold", "reason": "hold_sonnet_verdict", "d1a_state": "HOLD", "routed_because": route}
    reason = "hold_sonnet_failed" if s["outcome"] in ("FAILED", "ERROR") else "hold_sonnet_cannot_tell"
    return {"decision": "hold", "reason": reason, "d1a_state": "CANNOT", "routed_because": route}
