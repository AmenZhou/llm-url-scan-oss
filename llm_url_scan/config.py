"""Configuration from LLMURL_* environment variables (names only here; values are paths and numbers, never secrets)."""
import os
from dataclasses import dataclass
from pathlib import Path


TEST_MODE_ACK = "LLMURL_TEST_MODE_I_UNDERSTAND_THIS_JUDGES_NOTHING"


@dataclass
class Config:
    data_dir: Path = Path.home() / ".llm-url-scan" / "data"
    anthropic_key_file: str = str(Path.home() / ".llm-url-scan" / "secrets" / "anthropic.env")
    anthropic_key_var: str = "LLMURL_ANTHROPIC_API_KEY"      # variable name inside the key file
    webrisk_key_file: str = str(Path.home() / ".llm-url-scan" / "secrets" / "webrisk.env")
    daily_cap: float = 2.0
    total_cap: float = 20.0
    run_cap: float | None = None            # optional cap in USD for one run, with run_start = UTC time of the run's start
    run_start: str | None = None
    webrisk_daily_ceiling: int = 1000
    host: str = "127.0.0.1"
    port: int = 8800
    api_url: str = "http://127.0.0.1:8800"   # where the scheduler reaches the API's internal 6 h path
    worker_url: str = "http://capture:7100"      # the capture worker on api-net
    worker_token_file: str = "/run/worker/worker_token"
    could_not_scan: bool = True                  # LLMURL_COULD_NOT_SCAN=0: unreadable pages are holds again and the page-fact detector is off
    shop_routing: bool = False                   # LLMURL_SHOP_ROUTING=1: a Sonnet look at Haiku-passed pages that show a price and a cart phrase (off unless exactly "1")
    test_mode: bool = False                    # stack tests only: a fake judge and fake Web Risk, no key file read (LLMURL_TEST_MODE=1)

    @classmethod
    def from_env(cls, env=os.environ):
        c, g = cls(), env.get
        c.data_dir = Path(g("LLMURL_DATA_DIR", str(c.data_dir)))
        c.anthropic_key_file = g("LLMURL_ANTHROPIC_KEY_FILE", c.anthropic_key_file)
        c.anthropic_key_var = g("LLMURL_ANTHROPIC_KEY_VAR", c.anthropic_key_var)
        c.webrisk_key_file = g("LLMURL_WEBRISK_KEY_FILE", c.webrisk_key_file)
        c.daily_cap = float(g("LLMURL_DAILY_CAP_USD", c.daily_cap))
        c.total_cap = float(g("LLMURL_TOTAL_CAP_USD", c.total_cap))
        c.run_cap = float(g("LLMURL_RUN_CAP_USD")) if g("LLMURL_RUN_CAP_USD") else None
        c.run_start = g("LLMURL_RUN_START")
        c.webrisk_daily_ceiling = int(g("LLMURL_WEBRISK_DAILY_CEILING", c.webrisk_daily_ceiling))
        c.host, c.port = g("LLMURL_HOST", c.host), int(g("LLMURL_PORT", c.port))
        c.api_url = g("LLMURL_API_URL", c.api_url)
        c.worker_url = g("LLMURL_WORKER_URL", c.worker_url)
        c.worker_token_file = g("LLMURL_WORKER_TOKEN_FILE", c.worker_token_file)
        c.could_not_scan = g("LLMURL_COULD_NOT_SCAN", "1") != "0"
        c.shop_routing = g("LLMURL_SHOP_ROUTING", "0") == "1"
        c.test_mode = g("LLMURL_TEST_MODE") == "1"
        if c.test_mode and g(TEST_MODE_ACK) != "1":
            raise SystemExit("LLMURL_TEST_MODE=1 replaces the judge with a fake that judges nothing; set " + TEST_MODE_ACK + "=1 as well, or unset LLMURL_TEST_MODE.")
        return c
