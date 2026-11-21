"""Salted ids, the sealed address store, secrets init, the spend ledger and the breakers."""
import os
import sqlite3
import stat
from datetime import datetime, timedelta, timezone

import pytest
from cryptography.exceptions import InvalidTag

from llm_url_scan import cli
from llm_url_scan.config import Config
from llm_url_scan.keys import caller_for, init_secrets, load_callers, load_private_key, load_public_key, load_salt, read_env_value, KeyError_
from llm_url_scan.ledger import Ledger, SpendCap
from llm_url_scan.store import RecheckStore, canonical, hid_of

NOW = datetime(2026, 11, 20, 12, 0, 0, tzinfo=timezone.utc)
ADDR = "https://shop-7.brandx.example/login?u=abc"


def mode(p):
    return stat.S_IMODE(os.stat(p).st_mode)


def test_init_creates_0600_secrets_and_never_overwrites(tmp_path, capsys):
    d = tmp_path / "data"
    assert init_secrets(d) == 1
    assert mode(d) == 0o700 and mode(d / "secrets") == 0o700
    for f in (d / "secrets").iterdir():
        assert mode(f) == 0o600
    pub = (d / "secrets" / "recheck_public.key").read_text()
    token = (d / "secrets" / "caller_token_owner").read_text()
    assert init_secrets(d) == 2                          # a new salt version, the key pair and the token stay
    assert (d / "secrets" / "recheck_public.key").read_text() == pub and (d / "secrets" / "caller_token_owner").read_text() == token
    assert load_salt(d)[0] == 2 and len(load_salt(d)[1]) == 32
    assert caller_for(token, load_callers(d)) == "owner" and caller_for("wrong", load_callers(d)) is None and caller_for("", load_callers(d)) is None


def test_cli_init_prints_no_secret(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("LLMURL_DATA_DIR", str(tmp_path / "d"))
    assert cli.main(["init"]) == 0
    out = capsys.readouterr().out
    assert out.strip() == "created salt version 1"
    assert (tmp_path / "d" / "secrets" / "caller_token_owner").read_text() not in out


def test_read_env_value_never_echoes(tmp_path):
    f = tmp_path / "k.env"
    f.write_text("OTHER=1\nMYVAR='abcdefghijk'\n")
    assert read_env_value(f, "MYVAR") == "abcdefghijk"
    for bad in ("NOPE", "OTHER"):
        with pytest.raises(KeyError_) as e:
            read_env_value(f, bad)
        assert "abcdefghijk" not in str(e.value)
    with pytest.raises(KeyError_):
        read_env_value(tmp_path / "missing.env", "X")


def test_hid_is_salted_and_canonical():
    salt = b"s" * 32
    a = hid_of(salt, "HTTP://Shop-7.BrandX.example:80/a?q=1#frag")
    assert a == hid_of(salt, "http://shop-7.brandx.example/a?q=1") and len(a) == 64
    assert a != hid_of(b"t" * 32, "http://shop-7.brandx.example/a?q=1")
    assert a != hid_of(salt, "http://shop-7.brandx.example/a?q=2")
    assert canonical("https://bücher.example:8443/x") == "https://xn--bcher-kva.example:8443/x"


@pytest.fixture
def store(tmp_path):
    d = tmp_path / "d"
    init_secrets(d)
    path = tmp_path / "recheck.sqlite"
    return RecheckStore(path, public=load_public_key(d), private=load_private_key(d)), path, d


def test_sealed_round_trip_and_delete(store):
    s, path, d = store
    hid = "a" * 64
    s.insert(hid, 1, ADDR, NOW, r6=True)
    assert s.read(hid, 1) == ADDR
    (row,) = s.rows()
    assert row[0] == hid and row[2] == "2026-11-27T12:00:00Z" and row[3] == "2026-11-20T18:00:00Z"
    assert ADDR not in repr(row) and "brandx" not in repr(row)
    s.delete(hid, 1)
    assert s.rows() == []
    assert b"brandx" not in path.read_bytes()


def test_row_without_r6_has_no_six_hour_due(store):
    s, _p, _d = store
    s.insert("b" * 64, 1, ADDR, NOW)
    assert s.rows()[0][3] is None


def test_address_never_in_the_file_and_nonce_is_random(store):
    s, path, _ = store
    s.insert("a" * 64, 1, ADDR, NOW)
    s.insert("b" * 64, 1, ADDR, NOW)
    raw = path.read_bytes()
    assert b"brandx" not in raw and b"shop-7" not in raw
    n = [r[0] for r in sqlite3.connect(path).execute("SELECT nonce FROM recheck")]
    assert len(set(n)) == 2 and all(len(x) == 12 for x in n)
    assert mode(path) == 0o600 and s.db.execute("PRAGMA secure_delete").fetchone()[0] == 1


def test_aad_binds_hid_and_salt_version(store):
    s, path, _ = store
    s.insert("a" * 64, 1, ADDR, NOW)
    s.db.execute("UPDATE recheck SET hid=? ", ("c" * 64,))
    with pytest.raises(InvalidTag):
        s.read("c" * 64, 1)
    s.db.execute("UPDATE recheck SET hid=?, salt_ver=2", ("a" * 64,))
    with pytest.raises(InvalidTag):
        s.read("a" * 64, 2)


def test_api_side_store_can_insert_but_not_read(tmp_path):
    d = tmp_path / "d"
    init_secrets(d)
    api = RecheckStore(tmp_path / "r.sqlite", public=load_public_key(d))
    api.insert("a" * 64, 1, ADDR, NOW)
    with pytest.raises(Exception):
        api.read("a" * 64, 1)
    sched = RecheckStore(tmp_path / "r.sqlite", private=load_private_key(d))
    assert sched.read("a" * 64, 1) == ADDR


def test_purge_older_than_ten_days(store):
    s, _p, _ = store
    s.insert("a" * 64, 1, ADDR, NOW - timedelta(days=11))
    s.insert("b" * 64, 1, ADDR, NOW - timedelta(days=9))
    assert s.purge_older(NOW) == [("a" * 64, 1)]
    assert [r[0] for r in s.rows()] == ["b" * 64]


# ---------------------------------------------------------------- ledger
class Clock:
    def __init__(self):
        self.t = NOW

    def __call__(self):
        return self.t


def ledger(tmp_path, daily=2.0, total=20.0, **kw):
    clock = kw.pop("clock", Clock())
    return Ledger(tmp_path / "l.sqlite", daily, total, clock=clock, **kw), clock


def test_reserve_settle_and_daily_cap(tmp_path):
    lg, _ = ledger(tmp_path, daily=0.30)
    a = lg.reserve(0.12)
    b = lg.reserve(0.12)
    with pytest.raises(SpendCap):
        lg.reserve(0.12)                      # 0.36 would pass the 0.30 cap
    lg.settle(a, 0.001)
    lg.settle(b, 0.002)
    assert lg.spent() == (0.003, 0.003)
    lg.reserve(0.12)                          # a measured cost frees the headroom


def test_day_boundary_and_total_cap(tmp_path):
    lg, clock = ledger(tmp_path, daily=1.0, total=1.5)
    lg.settle(lg.reserve(0.9), 0.9)
    with pytest.raises(SpendCap):
        lg.reserve(0.2)
    clock.t += timedelta(days=1)
    lg.settle(lg.reserve(0.5), 0.5)           # new day: daily is free again
    with pytest.raises(SpendCap):
        lg.reserve(0.2)                       # but the total cap (1.5) would be passed: 1.4 + 0.2


def test_run_cap_counts_only_the_run(tmp_path):
    lg, _ = ledger(tmp_path, daily=10, total=10, run_cap=1.0, run_start="2026-11-20T12:00:00Z")
    lg.settle(lg.reserve(0.9), 0.9)
    with pytest.raises(SpendCap):
        lg.reserve(0.2)


def test_open_reservation_stays_charged_after_a_restart(tmp_path):
    lg, clock = ledger(tmp_path, daily=0.2)
    lg.reserve(0.15)                          # never settled: the process died
    lg2, _ = ledger(tmp_path, daily=0.2, clock=clock)
    with pytest.raises(SpendCap):
        lg2.reserve(0.1)
    assert lg2.spent()[0] == 0.15


def test_topup_checks_the_caps(tmp_path):
    lg, _ = ledger(tmp_path, daily=0.2)
    rid = lg.reserve(0.12)
    lg.topup(rid, 0.15)
    with pytest.raises(SpendCap):
        lg.topup(rid, 0.25)
    assert lg.spent()[0] == 0.15


def test_web_risk_daily_ceiling(tmp_path):
    lg, clock = ledger(tmp_path)
    assert [lg.wr_allow(2) for _ in range(3)] == [True, True, False]
    clock.t += timedelta(days=1)
    assert lg.wr_allow(2)


def test_breaker_on_refusal_rate_needs_20_scans_and_resume_restarts_the_window(tmp_path):
    lg, _ = ledger(tmp_path)
    for _ in range(19):
        assert lg.record_scan(0.003, True, False, False, False) == []        # fewer than 20: not active
    assert lg.record_scan(0.003, True, False, False, False) == ["refusal_content"]
    assert lg.open_kinds() == ["refusal_content"]
    assert lg.resume("refusal_content") and lg.open_kinds() == []
    assert lg.record_scan(0.003, True, False, False, False) == []            # the window restarted


@pytest.mark.parametrize("flags,kind", [((False, True, False, False), "parse_storm"), ((False, False, True, False), "maxtok_storm")])
def test_other_rate_breakers(tmp_path, flags, kind):
    lg, _ = ledger(tmp_path)
    got = []
    for _ in range(20):
        got = lg.record_scan(0.003, *flags)
    assert got == [kind]


def test_mean_cost_breaker_at_1_25_times_plan_mean(tmp_path):
    lg, _ = ledger(tmp_path)
    for _ in range(20):
        assert lg.record_scan(0.0110, False, False, False, False) == []
    lg2 = Ledger(tmp_path / "m.sqlite", 2, 20)
    got = []
    for _ in range(20):
        got = lg2.record_scan(0.0115, False, False, False, False)
    assert got == ["meancost"]


def test_three_consecutive_api_errors(tmp_path):
    lg, _ = ledger(tmp_path)
    assert lg.record_scan(0.0, False, False, False, True) == []
    assert lg.record_scan(0.0, False, False, False, True) == []
    assert lg.record_scan(0.0, False, False, False, True) == ["errors3"]


def test_final_breaker_needs_a_change_before_resume(tmp_path):
    lg, _ = ledger(tmp_path)
    lg.open_breaker("shape400")
    assert lg.resume("shape400") is False and lg.open_kinds() == ["shape400"]
    assert lg.resume("shape400", changed=True) and lg.open_kinds() == []
