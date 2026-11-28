import builtins
import json
import re

import pytest

from evals import replay as R

PROMPT = R.judge.load_prompt()
LONG = "Welcome to the made-up page. " * 60       # more than 1,000 characters of text
FORM = "<form action='/go'><input type=password name=pw></form>"
MONEY_FORM = "<form action='/pay'><input type=text name=cardnumber placeholder='Card number'><input type=text name=cvv></form>"


def page(pid, marker, body=LONG, forms=FORM, label="benign"):
    html = "<html><head><title>%s</title></head><body><p>%s</p>%s</body></html>" % (marker, body, forms)
    return {"id": pid, "label": label, "url": "https://example.test/%s" % pid, "html": html}


def answer(verdict, rules=()):
    body = {"verdict": verdict, "rules": list(rules), "brand": None, "quotes": [], "injection_text": False}
    return {"id": "msg_test", "stop_reason": "end_turn", "usage": {"input_tokens": 1000, "output_tokens": 100}, "content": [{"type": "text", "text": json.dumps(body)}]}


class Fake:
    """Fake client: reply(model, content) -> response dict. Records every call."""

    def __init__(self, reply):
        self.reply, self.calls, self.messages = reply, [], self

    def create(self, **kw):
        self.calls.append(kw["model"])
        return self.reply(kw["model"], kw["messages"][0]["content"])


def run(tmp_path, pages, fake, arms, run_cap=50.0, grand_cap=50.0, repeats=1, ledger=None):
    tmp_path.mkdir(parents=True, exist_ok=True)
    led = ledger or R.Ledger(str(tmp_path / "ledger.jsonl"))
    n = R.run_arms(pages, arms, fake, led, "R1", run_cap, grand_cap, str(tmp_path / "out"), repeats)
    lines = {}
    for a in arms:
        p = tmp_path / "out" / ("R1-%s.jsonl" % a.name)
        lines[a.name] = [json.loads(x) for x in open(p)] if p.exists() else []
    return n, lines, led


BASE, MONEY = R.Arm("BASE", PROMPT), R.Arm("MONEY", PROMPT, route_money=True)


def test_base_follows_the_service_routing_and_records_every_call(tmp_path):
    plan = {"page-a": ("benign", None), "page-b": ("phishing", "benign"), "page-c": ("phishing", "phishing"), "page-d": ("cannot_tell", "cannot_tell")}

    def reply(model, content):
        h, s = plan[re.search(r"title: (page-\w)", content).group(1)]
        return answer(h, ["R5"] if h == "phishing" else []) if "haiku" in model else answer(s, ["R7"] if s == "cannot_tell" else [])
    pages = [page(str(k), m) for k, m in enumerate(plan)]
    n, lines, _ = run(tmp_path, pages, Fake(reply), [BASE])
    got = [(r["decision"], r["reason"], len(r["calls"])) for r in lines["BASE"]]
    assert got == [("pass", "pass_haiku", 1), ("pass", "pass_sonnet_overrode_hold", 2), ("hold", "hold_sonnet_verdict", 2), ("hold", "hold_sonnet_cannot_tell", 2)]
    c = lines["BASE"][2]["calls"][0]
    assert c["verdict"] == "phishing" and c["rules"] == ["R5"] and c["outcome"] == "HOLD" and c["in"] == 1000 and c["out"] == 100 and c["cost"] > 0
    assert lines["BASE"][2]["cost"] == pytest.approx(sum(x["cost"] for x in lines["BASE"][2]["calls"]))


def test_results_carry_no_url_title_or_text(tmp_path):
    run(tmp_path, [page("1", "page-zzz-marker")], Fake(lambda m, c: answer("benign")), [BASE])
    raw = open(tmp_path / "out" / "R1-BASE.jsonl").read()
    assert "example.test" not in raw and "page-zzz-marker" not in raw and "Welcome" not in raw and "http" not in raw
    assert set(json.loads(raw)) == {"id", "arm", "repeat", "run", "label", "decision", "judge_decision", "reason", "routed_because", "short", "money", "calls", "cost"}


def test_route_money_sends_payment_or_price_pages_to_sonnet_even_when_haiku_passes(tmp_path):
    pages = [page("pay", "page-pay", forms=MONEY_FORM), page("price", "page-price", body=LONG + " Only $19.99 today"), page("plain", "page-plain")]

    def reply(model, content):
        return answer("benign") if "haiku" in model else answer("phishing", ["R5"])
    fake = Fake(reply)
    _, lines, _ = run(tmp_path, pages, fake, [BASE, MONEY])
    assert [len(r["calls"]) for r in lines["BASE"]] == [1, 1, 1] and [r["decision"] for r in lines["BASE"]] == ["pass"] * 3
    assert [len(r["calls"]) for r in lines["MONEY"]] == [2, 2, 1]
    assert [r["routed_because"] for r in lines["MONEY"]] == ["money", "money", None]
    assert [(r["decision"], r["reason"]) for r in lines["MONEY"][:2]] == [("hold", "hold_sonnet_verdict")] * 2
    assert [r["money"] for r in lines["BASE"]] == [True, True, False]


def test_route_money_reason_when_sonnet_confirms_pass(tmp_path):
    _, lines, _ = run(tmp_path, [page("pay", "page-pay", forms=MONEY_FORM)], Fake(lambda m, c: answer("benign")), [MONEY])
    assert (lines["MONEY"][0]["decision"], lines["MONEY"][0]["reason"]) == ("pass", "pass_sonnet_confirmed_money")


def test_ledger_run_and_grand_caps_refuse(tmp_path):
    fake = Fake(lambda m, c: answer("benign"))
    one = R.judge.reservation([R.judge.HAIKU], R.judge.INPUT_UPPER)
    pages = [page(str(i), "page-p%d" % i) for i in range(3)]
    n, lines, led = run(tmp_path / "ok", pages, fake, [BASE], run_cap=2.5 * one)      # each call settles far below its reservation, so all 3 fit
    assert n["lines"] == 3
    seed = tmp_path / "seed.jsonl"
    seed.write_text(json.dumps({"call": "s", "run": "R0", "reserved": 9.99}) + "\n" + json.dumps({"call": "s", "actual": 9.99}) + "\n")
    n, lines, _ = run(tmp_path / "grand", pages, fake, [BASE], grand_cap=9.995, ledger=R.Ledger(str(seed)))      # 9.99 already spent by another run
    assert n["stopped_ledger_grand"] == 1 and "lines" not in n and lines["BASE"] == [] and fake.calls.count(R.judge.HAIKU) == 3
    n, lines, _ = run(tmp_path / "run", pages, fake, [BASE], run_cap=one / 2)
    assert n["stopped_ledger_run"] == 1 and lines["BASE"] == [] and fake.calls.count(R.judge.HAIKU) == 3      # refused before any call


def test_two_ledgers_on_one_file_see_each_others_spend(tmp_path):
    path = str(tmp_path / "ledger.jsonl")
    first, second = R.Ledger(path), R.Ledger(path)      # two replay processes opened the same ledger
    first.reserve("R1", 6.0, run_cap=10, grand_cap=10)
    with pytest.raises(R.Refused, match="grand"):
        second.reserve("R2", 6.0, run_cap=10, grand_cap=10)      # 6 + 6 would pass the grand cap of 10
    assert second.spent() == 6.0 and R.Ledger(path).spent() == 6.0      # the refusal wrote nothing


def test_resume_skips_finished_and_repeats_are_numbered(tmp_path):
    fake = Fake(lambda m, c: answer("benign"))
    pages = [page(str(i), "page-p%d" % i) for i in range(2)]
    n, lines, _ = run(tmp_path, pages, fake, [BASE], repeats=2)
    assert n["lines"] == 4 and sorted((r["id"], r["repeat"]) for r in lines["BASE"]) == [("0", 0), ("0", 1), ("1", 0), ("1", 1)]
    n2, lines2, _ = run(tmp_path, pages, fake, [BASE], repeats=3)
    assert n2["skipped"] == 4 and n2["lines"] == 2 and len(lines2["BASE"]) == 6


def test_credit_failure_halts(tmp_path):
    class Boom(Exception):
        status_code = 402

    def reply(model, content):
        raise Boom("credit balance low")
    n, lines, _ = run(tmp_path, [page("1", "page-a"), page("2", "page-b")], Fake(reply), [BASE])
    assert n["stopped_credit"] == 1 and lines["BASE"] == []


def test_run_never_reads_the_key(tmp_path, monkeypatch):
    opened = []
    real = builtins.open
    monkeypatch.setattr(builtins, "open", lambda f, *a, **k: (opened.append(str(f)), real(f, *a, **k))[1])
    monkeypatch.setattr(R.keys, "read_env_value", lambda *a, **k: (_ for _ in ()).throw(AssertionError("key read")))
    run(tmp_path, [page("1", "page-a")], Fake(lambda m, c: answer("benign")), [BASE])
    assert not any("secrets" in x or x.endswith(".env") for x in opened)


def test_load_pages_and_parse_arm(tmp_path):
    (tmp_path / "pages").mkdir()
    for i in ("b", "a"):
        (tmp_path / "pages" / (i + ".json")).write_text(json.dumps({"url": "https://example.test/", "html": "<p>x</p>", "label": "benign"}))
    ids = tmp_path / "ids.txt"
    ids.write_text("b\na\n")
    assert [p["id"] for p in R.load_pages(str(tmp_path / "pages"), str(ids))] == ["a", "b"]
    pf = tmp_path / "p.md"
    pf.write_text("system prompt")
    a = R.parse_arm("X=%s+money" % pf)
    assert (a.name, a.prompt, a.route_money) == ("X", "system prompt", True) and R.parse_arm("Y=%s" % pf).route_money is False


# ---------------------------------------------------------------- the changed decision: detector and shop routing
CHANGED, OLD = R.Arm("CHANGED", PROMPT), R.Arm("OLD", PROMPT, legacy=True)
CHANGED_SHOP = R.Arm("CHANGED_SHOP", PROMPT, shop=True)
ERROR_PAGE = "<html><head><title>404 Not Found</title></head><body><p>The page you asked for is gone.</p></body></html>"
SHOP = "<html><head><title>page-shop</title></head><body><p>%s Price $19.99. Add to cart now.</p></body></html>" % LONG


def test_changed_arm_answers_could_not_scan_before_any_model_call_and_old_arm_still_asks_the_models(tmp_path):
    fake = Fake(lambda m, c: answer("benign"))
    _, lines, led = run(tmp_path, [{"id": "e", "label": "benign", "url": "https://example.test/e", "html": ERROR_PAGE}], fake, [CHANGED, OLD])
    c, o = lines["CHANGED"][0], lines["OLD"][0]
    assert (c["decision"], c["reason"], c["calls"], c["cost"]) == ("could_not_scan", "page_error", [], 0.0)
    assert o["decision"] == "pass" and len(o["calls"]) >= 1      # unchanged service: the models see the error page
    assert fake.calls.count(R.judge.HAIKU) == 1 and led.spent() > 0      # only the OLD arm spent


def test_only_a_shop_arm_sends_a_haiku_passed_shop_page_to_sonnet(tmp_path):
    def reply(model, content):
        return answer("benign") if "haiku" in model else answer("phishing", ["R5"])
    _, lines, _ = run(tmp_path, [{"id": "s", "label": "phishing", "url": "https://example.test/s", "html": SHOP}], Fake(reply), [CHANGED, CHANGED_SHOP, OLD])
    got = {k: (v[0]["decision"], v[0]["routed_because"], len(v[0]["calls"])) for k, v in lines.items()}
    assert got == {"CHANGED": ("pass", None, 1), "CHANGED_SHOP": ("hold", "shop_page", 2), "OLD": ("pass", None, 1)}      # no suffix = what ships


def test_parse_arm_flags(tmp_path):
    pf = tmp_path / "p.md"
    pf.write_text("x")
    a = R.parse_arm("X=%s+money+legacy" % pf)
    assert (a.route_money, a.legacy) == (True, True)
    assert (R.parse_arm("Y=%s+legacy" % pf).legacy, R.parse_arm("Z=%s" % pf).legacy) == (True, False)
    assert (R.parse_arm("S=%s+shop" % pf).shop, R.parse_arm("Z=%s" % pf).shop) == (True, False)


def test_routing_flags_are_refused_where_they_would_be_dropped(tmp_path, monkeypatch):
    pf = tmp_path / "p.md"
    pf.write_text("x")
    for spec in ("S=%s+shop+legacy", "A=%s+anyprice+legacy"):      # the legacy decision has no shop or price routing
        with pytest.raises(ValueError):
            R.parse_arm(spec % pf)
    monkeypatch.setattr(R, "PF", None)      # a build without page-fact rules (the unchanged baseline)
    with pytest.raises(ValueError):
        R.Arm("A", PROMPT, anyprice=True)
    assert R.Arm("OLD", PROMPT).anyprice is False      # a plain arm still builds


def test_duplicate_arm_names_are_refused(tmp_path):
    with pytest.raises(ValueError):
        run(tmp_path, [], Fake(lambda m, c: answer("benign")), [CHANGED, R.Arm("CHANGED", PROMPT, anyprice=True)])


# ---------------------------------------------------------------- +anyprice: any price amount routes a Haiku pass to Sonnet
ANYPRICE = R.Arm("ANYPRICE", PROMPT, anyprice=True)
PRICE_ONLY = "<html><head><title>page-price</title></head><body><p>%s Only $19.99 today.</p></body></html>" % LONG
NO_PRICE = "<html><head><title>page-none</title></head><body><p>%s Nothing for sale here.</p></body></html>" % LONG


def test_anyprice_routes_price_only_and_cart_pages_but_not_a_page_without_a_price(tmp_path):
    def reply(model, content):
        return answer("benign") if "haiku" in model else answer("phishing", ["R5"])
    pages = [{"id": i, "label": "phishing", "url": "https://example.test/" + i, "html": h} for i, h in (("p", PRICE_ONLY), ("c", SHOP), ("n", NO_PRICE))]
    _, lines, _ = run(tmp_path, pages, Fake(reply), [CHANGED, ANYPRICE])
    got = {(k, v["id"]): (v["decision"], v["routed_because"], len(v["calls"])) for k, vs in lines.items() for v in vs}
    assert got == {("CHANGED", "p"): ("pass", None, 1), ("CHANGED", "c"): ("pass", None, 1), ("CHANGED", "n"): ("pass", None, 1),
                   ("ANYPRICE", "p"): ("hold", "price_page", 2), ("ANYPRICE", "c"): ("hold", "price_page", 2), ("ANYPRICE", "n"): ("pass", None, 1)}


def test_anyprice_reason_when_sonnet_confirms_pass_and_it_wins_over_shop(tmp_path):
    both = R.Arm("BOTH", PROMPT, shop=True, anyprice=True)
    _, lines, _ = run(tmp_path, [{"id": "s", "label": "benign", "url": "https://example.test/s", "html": SHOP}], Fake(lambda m, c: answer("benign")), [both])
    assert (lines["BOTH"][0]["routed_because"], lines["BOTH"][0]["reason"]) == ("price_page", "pass_sonnet_confirmed_price")


def test_parse_arm_anyprice_suffix(tmp_path):
    pf = tmp_path / "p.md"
    pf.write_text("x")
    a = R.parse_arm("A=%s+anyprice" % pf)
    assert (a.anyprice, a.shop, a.legacy, a.route_money) == (True, False, False, False)
    b = R.parse_arm("B=%s+shop+anyprice+money" % pf)
    assert (b.anyprice, b.shop, b.route_money) == (True, True, True) and R.parse_arm("C=%s+shop" % pf).anyprice is False
