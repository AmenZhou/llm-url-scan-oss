"""Every row of the routing table, plus an independent restatement of the rule over every combination."""
import itertools

import pytest

from llm_url_scan.decide import decide, routed_because, state_of

PASS = {"outcome": "PASS", "reason": "verdict"}
HOLD = {"outcome": "HOLD", "reason": "verdict"}
CANNOT = {"outcome": "CAPTURE", "reason": "cannot_tell"}
EMPTY = {"outcome": "CAPTURE", "reason": "empty_page"}
FAILED = {"outcome": "FAILED", "reason": "max_tokens"}
ERROR = {"outcome": "ERROR", "reason": "api_error"}

def test_shop_route_only_for_a_long_haiku_pass():
    assert routed_because(PASS, False, True) == "shop_page"
    assert routed_because(PASS, False, False) is None
    assert routed_because(PASS, True, True) == "short_pass"      # short wins
    assert routed_because(HOLD, False, True) == "h_hold"         # a hold keeps its own route
    assert decide(PASS, PASS, False, True)["reason"] == "pass_sonnet_confirmed_shop"
    assert decide(PASS, HOLD, False, True) == {"decision": "hold", "reason": "hold_sonnet_verdict", "d1a_state": "HOLD", "routed_because": "shop_page"}
    assert decide(PASS, CANNOT, False, True)["reason"] == "hold_sonnet_cannot_tell"
    for broken in (FAILED, ERROR):      # a shop-routed Sonnet call that fails holds, as a short pass does
        assert (decide(PASS, broken, False, True)["decision"], decide(PASS, broken, False, True)["reason"]) == ("hold", "hold_sonnet_failed")


# (row, haiku, short, sonnet, decision, reason, routed_because)
ROWS = [
    (5, PASS, False, None, "pass", "pass_haiku", None),
    (6, PASS, True, PASS, "pass", "pass_sonnet_confirmed_short", "short_pass"),
    (7, PASS, True, HOLD, "hold", "hold_sonnet_verdict", "short_pass"),
    (8, PASS, True, CANNOT, "hold", "hold_sonnet_cannot_tell", "short_pass"),
    (8, PASS, True, EMPTY, "hold", "hold_sonnet_cannot_tell", "short_pass"),
    (9, PASS, True, FAILED, "hold", "hold_sonnet_failed", "short_pass"),
    (9, PASS, True, ERROR, "hold", "hold_sonnet_failed", "short_pass"),
    (10, HOLD, False, PASS, "pass", "pass_sonnet_overrode_hold", "h_hold"),
    (10, HOLD, True, PASS, "pass", "pass_sonnet_overrode_hold", "h_hold"),
    (11, HOLD, False, HOLD, "hold", "hold_sonnet_verdict", "h_hold"),
    (12, HOLD, False, CANNOT, "hold", "hold_sonnet_cannot_tell", "h_hold"),
    (12, HOLD, True, EMPTY, "hold", "hold_sonnet_cannot_tell", "h_hold"),
    (13, HOLD, False, FAILED, "hold", "hold_sonnet_failed", "h_hold"),
    (13, HOLD, False, ERROR, "hold", "hold_sonnet_failed", "h_hold"),
    (14, CANNOT, False, PASS, "pass", "pass_sonnet_resolved", "h_cannot"),
    (14, EMPTY, True, PASS, "pass", "pass_sonnet_resolved", "h_cannot"),
    (15, CANNOT, False, HOLD, "hold", "hold_sonnet_verdict", "h_cannot"),
    (16, CANNOT, False, CANNOT, "hold", "hold_sonnet_cannot_tell", "h_cannot"),
    (16, CANNOT, True, EMPTY, "hold", "hold_sonnet_cannot_tell", "h_cannot"),
    (17, CANNOT, False, FAILED, "hold", "hold_sonnet_failed", "h_cannot"),
    (17, CANNOT, False, ERROR, "hold", "hold_sonnet_failed", "h_cannot"),
    (18, FAILED, False, PASS, "pass", "pass_sonnet_resolved", "h_failed"),
    (18, ERROR, True, PASS, "pass", "pass_sonnet_resolved", "h_failed"),
    (19, FAILED, False, HOLD, "hold", "hold_sonnet_verdict", "h_failed"),
    (19, ERROR, False, HOLD, "hold", "hold_sonnet_verdict", "h_failed"),
    (20, FAILED, False, CANNOT, "hold", "hold_sonnet_cannot_tell", "h_failed"),
    (20, ERROR, False, FAILED, "hold", "hold_sonnet_failed", "h_failed"),
]


@pytest.mark.parametrize("row,h,short,s,decision,reason,route", ROWS, ids=["row%d-%d" % (r[0], i) for i, r in enumerate(ROWS)])
def test_every_row_of_the_d1a_table(row, h, short, s, decision, reason, route):
    d = decide(h, s, short)
    assert (d["decision"], d["reason"], d["routed_because"]) == (decision, reason, route)
    assert d["d1a_state"] == ("PASS" if decision == "pass" else ("HOLD" if state_of(s) == "HOLD" else "CANNOT"))


def test_all_table_rows_are_covered():
    assert {r[0] for r in ROWS} == set(range(5, 21))


def test_matches_the_rule_restated_for_every_combination():
    """Final state is Sonnet's when it ran, else PASS; CANNOT is a hold. Sonnet runs when h in (HOLD, CANNOT) or (h == PASS and short)."""
    recs = [PASS, HOLD, CANNOT, EMPTY, FAILED, ERROR]
    for h, s, short in itertools.product(recs, recs, (False, True)):
        hs, ss = state_of(h), state_of(s)
        routed = hs in ("HOLD", "CANNOT") or (hs == "PASS" and short)
        assert (routed_because(h, short) is not None) == routed
        want = ss if (short and hs == "PASS") else ("PASS" if hs == "PASS" else ss)
        d = decide(h, s if routed else None, short)
        assert d["d1a_state"] == (want if routed else "PASS")
        assert d["decision"] == ("pass" if d["d1a_state"] == "PASS" else "hold")
