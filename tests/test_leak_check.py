"""The pre-publish leak check flags real-looking leaks and lets reserved test names through."""
import importlib.util
from pathlib import Path

spec = importlib.util.spec_from_file_location("leak_check", Path(__file__).parent.parent / "scripts" / "leak_check.py")
LC = importlib.util.module_from_spec(spec)
spec.loader.exec_module(LC)


def test_reserved_and_allowed_names_pass():
    for line in ('url = "https://login.brandx.example/a?b=1"', "http://x.test/", "https://example.com/", "http://localhost:8800/",
                 "https://api.anthropic.com", "see https://github.com/owner/repo", "plain text, no address",
                 "http://user:pw@x.test/", "http://intranet/", "http://127.0.0.1/"):
        assert LC.findings(line) == [], line


def test_leaks_are_flagged_by_kind(monkeypatch):
    monkeypatch.setenv("LEAK_CHECK_PRIVATE_WORDS", "secretset, other")
    assert LC.findings("go to https://real-shop.com/login") == ["unlisted_host"]      # leak-ok
    assert LC.findings("http://user:pw@real-shop.com/") == ["unlisted_host"]         # leak-ok
    assert LC.findings('KEY = "/Users/someone/secrets/a.env"') == ["home_path"]       # leak-ok
    assert LC.findings("token sk-ant-abcdef123456") == ["api_key"]                    # leak-ok
    assert LC.findings("-----BEGIN RSA PRIVATE KEY-----") == ["private_key"]          # leak-ok
    assert LC.findings("results on SecretSet pages") == ["private_word"]


def test_a_reviewed_line_can_be_accepted():
    assert LC.findings("https://www.real-site.org/ leak-ok") == []      # leak-ok
