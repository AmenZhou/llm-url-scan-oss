"""Commands: init (generate secrets), serve, resume (owner only), status, recheck-once / recheck-loop (scheduler), report (weekly counts).
python -m llm_url_scan <command>"""
import os
import sys
from datetime import datetime, timezone

from . import recheck, report
from .app import LOG_CONFIG, create_app, install_excepthooks
from .capture import make_client
from .config import Config
from .judge import build_client, load_prompt
from .keys import KeyError_, init_secrets, load_callers, load_private_key, load_public_key, load_salt, read_env_value
from .ledger import Ledger
from .logs import LogWriter
from .service import Service
from .store import RecheckStore
from .webrisk import KEY_VAR as WR_KEY_VAR
from .webrisk import WebRisk


def check_env():
    """Refuse to start when an environment variable could redirect or log the model traffic (names only, never values)."""
    bad = sorted(k for k in os.environ if k.upper().startswith("ANTHROPIC_") or any(w in k.upper() for w in ("_LOG", "CUSTOM_HEADERS", "PROXY", "KEYLOG")))
    if bad:
        raise KeyError_("forbidden environment variable(s) set: " + ", ".join(bad))


def build_service(cfg, client=None, webrisk=None, capture=None, **kw):
    """Assemble the service from the data dir. Injected client / webrisk / capture replace the real ones (tests)."""
    d = cfg.data_dir
    ledger = Ledger(d / "ledger.sqlite", cfg.daily_cap, cfg.total_cap, cfg.run_cap, cfg.run_start or "", **{k: kw[k] for k in ("clock",) if k in kw})
    salt_ver, salt = load_salt(d)
    if cfg.test_mode:      # explicit test flag only (compose test override): fake judge and Web Risk, no key file is read
        from .testmode import FakeJudge, FakeWebRisk
        client, webrisk = client or FakeJudge(), webrisk or FakeWebRisk()
    client = client or build_client(read_env_value(cfg.anthropic_key_file, cfg.anthropic_key_var))
    webrisk = webrisk or WebRisk(read_env_value(cfg.webrisk_key_file, WR_KEY_VAR), allow=lambda: ledger.wr_allow(cfg.webrisk_daily_ceiling))
    svc = Service(client=client, webrisk=webrisk, capture=capture or make_client(cfg), ledger=ledger, log=LogWriter(d), store=RecheckStore(d / "recheck.sqlite", public=load_public_key(d)),
                  salt=salt, salt_ver=salt_ver, prompt=load_prompt(), could_not_scan=cfg.could_not_scan, shop_routing=cfg.shop_routing, **kw)
    return svc


def scheduler_parts(cfg):
    """The scheduler's pieces: the store with the private key only (no salt), Web Risk under the shared daily ceiling, the log,
    and the hand-off to the API's internal 6 h path with the scheduler token."""
    d = cfg.data_dir
    ledger = Ledger(d / "ledger.sqlite", cfg.daily_cap, cfg.total_cap, cfg.run_cap, cfg.run_start or "")
    store = RecheckStore(d / "recheck.sqlite", private=load_private_key(d))
    wr = WebRisk(read_env_value(cfg.webrisk_key_file, WR_KEY_VAR), allow=lambda: ledger.wr_allow(cfg.webrisk_daily_ceiling))
    token = (d / "secrets" / "caller_token_scheduler").read_text().strip()
    return store, wr, LogWriter(d), recheck.api_r6(cfg.api_url, token)


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    cmd = argv[0] if argv else ""
    cfg = Config.from_env()
    try:
        if cmd == "init":
            print("created salt version %d" % init_secrets(cfg.data_dir))
        elif cmd == "serve":
            import uvicorn
            check_env()
            install_excepthooks()
            svc = build_service(cfg)
            uvicorn.run(create_app(svc, load_callers(cfg.data_dir)), host=cfg.host, port=cfg.port, log_config=LOG_CONFIG, access_log=False)
        elif cmd == "resume" and len(argv) >= 2:
            svc = build_service(cfg, client=object(), webrisk=object(), capture=object())
            ok = svc.ledger.resume(argv[1], changed="--changed" in argv)
            if ok:
                svc.log.write("breaker", kind=argv[1], state="resumed")
            print("resumed %s" % argv[1] if ok else "nothing resumed")
        elif cmd in ("recheck-once", "recheck-loop"):
            check_env()
            install_excepthooks()
            store, wr, log, r6 = scheduler_parts(cfg)
            if cmd == "recheck-once":
                n = recheck.run_once(store, wr, log, datetime.now(timezone.utc), r6)
                print(" ".join("%s=%d" % kv for kv in sorted(n.items())))
            else:
                recheck.loop(store, wr, log, r6)
        elif cmd == "report":
            y, w = report.parse_week(argv[2]) if len(argv) >= 3 and argv[1] == "--week" else report.this_week()
            print(report.build(report.load(cfg.data_dir), y, w), end="")
        elif cmd == "status":
            svc = build_service(cfg, client=object(), webrisk=object(), capture=object())
            print(svc.status())
        else:
            print("usage: python -m llm_url_scan init | serve | resume <kind> [--changed] | status | recheck-once | recheck-loop | report [--week YYYY-Www]")
            return 2
    except KeyError_ as e:
        print("refused: %s" % e)
        return 2
    except Exception as e:      # class name only
        print("error: %s" % type(e).__name__)
        return 4
    return 0
