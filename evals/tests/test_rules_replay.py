from evals import rules_replay as RR

HIST = RR.History([
    ("https://shop.badsite.test/x", "phish", "2020-01-01"),
    ("https://badsite.test/y", "phish", "2022-01-01"),
    ("https://goodsite.test/a", "benign", "2020-06-01"),
    ("https://goodsite.test/b", "benign", "2022-06-01"),
    ("https://mixed.test/a", "phish", "2020-01-01"),
    ("https://mixed.test/b", "benign", "2020-01-02"),
    ("https://alice.github.io/p", "phish", "2020-01-01"),
])


def row(i, decision, reason="pass_haiku", label="benign"):
    return {"id": i, "label": label, "decision": decision, "reason": reason, "cost": 0.1}


def meta(**pages):
    return {i: {"id": i, "url": u, "date": d} for i, (u, d) in pages.items()}


def run(rows, m, **kw):
    out, strata = RR.replay(rows, m, HIST, **kw)
    return {r["id"]: r for r in out}, strata


def test_domain_helpers():
    assert RR.domain_of("https://a.b.badsite.test/x") == "badsite.test" and RR.domain_of("https://x.co.uk/p") == "x.co.uk"
    assert RR.domain_of("noscheme.test/p") == "noscheme.test"


def test_known_site_is_time_ordered_by_default():
    m = meta(late=("https://badsite.test/z", "2021-01-01"), early=("https://badsite.test/z", "2019-01-01"), same_day=("https://badsite.test/z", "2020-01-01"))
    rows = [row(i, "pass") for i in m]
    out, strata = run(rows, m)
    assert out["late"]["decision"] == "hold" and out["late"]["rule"] == "known_site" and out["late"]["judge_decision"] == "pass"
    assert out["early"]["decision"] == "pass" and "rule" not in out["early"] and strata["early"] == "unknown"      # history is dated after the page
    assert out["same_day"]["decision"] == "pass"      # only pages strictly before
    out_all, strata_all = run(rows, m, mode="all")
    assert {i: r["decision"] for i, r in out_all.items()} == {"late": "hold", "early": "hold", "same_day": "hold"} and strata_all["early"] == "phish_only"
    assert out_all["early"]["history"] == "all" and out["early"]["history"] == "time"


def test_known_site_skips_mixed_unknown_held_and_shared_hosts():
    m = meta(mixed=("https://mixed.test/q", "2021-01-01"), unknown=("https://nothing.test/q", "2021-01-01"), held=("https://badsite.test/q", "2021-01-01"),
             shared=("https://bob.github.io/q", "2021-01-01"))
    rows = [row("mixed", "pass"), row("unknown", "pass"), row("held", "hold", "hold_sonnet_verdict"), row("shared", "pass")]
    out, strata = run(rows, m)
    assert [out[i]["decision"] for i in ("mixed", "unknown", "held", "shared")] == ["pass", "pass", "hold", "pass"] and strata["mixed"] == "mixed"
    assert "rule" not in out["held"]      # already held: nothing added
    assert run(rows, m, exceptions=set())[0]["shared"]["decision"] == "hold"      # without the exception list the shared host is caught


def test_shared_host_exception_below_a_registrable_domain():
    # "sites.google.com" is a host, not a registrable domain: pages under it must still be skipped
    hist = RR.History([("https://x.sites.google.com/p", "phish", "2020-01-01")])
    m = meta(site=("https://y.sites.google.com/q", "2021-01-01"), plain=("https://google.com/q", "2021-01-01"))
    out, _ = RR.replay([row("site", "pass"), row("plain", "pass")], m, hist, rules=("known_site",), exceptions={"sites.google.com"})
    assert out[0]["decision"] == "pass" and out[1]["decision"] == "hold"


def test_tiebreak_passes_cannot_tell_on_clean_history_only():
    m = meta(clean=("https://goodsite.test/q", "2021-01-01"), young=("https://goodsite.test/q", "2020-01-01"), bad=("https://badsite.test/q", "2021-01-01"))
    rows = [row(i, "hold", "hold_sonnet_cannot_tell") for i in m]
    out, _ = run(rows, m, rules=("tiebreak",))
    assert out["clean"]["decision"] == "pass" and out["clean"]["rule"] == "tiebreak"
    assert out["young"]["decision"] == "hold" and out["bad"]["decision"] == "hold"      # no history yet / not a clean site
    out2, _ = run([row("c", "hold", "hold_sonnet_verdict")], meta(c=("https://goodsite.test/q", "2021-01-01")), rules=("tiebreak",))
    assert out2["c"]["decision"] == "hold"      # a real Sonnet hold is never overturned
    out3, _ = run(rows, m, rules=("known_site",))
    assert out3["clean"]["decision"] == "hold"      # rule selection


def test_rows_without_meta_are_unchanged():
    out, strata = run([row("x", "pass")], {})
    assert out["x"]["decision"] == "pass" and strata["x"] == "unknown"
