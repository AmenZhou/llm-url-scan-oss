"""The pre-publish leak check flags real-looking leaks and lets reserved test names through."""
import importlib.util
import subprocess
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


def test_other_key_kinds_schemes_and_lookalike_hosts_are_flagged():
    assert LC.findings("k = AIza" + "B" * 35) == ["api_key"]
    assert LC.findings("k = AKIA" + "ABCDEFGHIJKLMNOP") == ["api_key"]
    assert LC.findings("t = ghp_" + "a" * 36) == ["api_key"]
    assert LC.findings("https://counterexample.com/") == ["unlisted_host"]      # leak-ok
    assert LC.findings("db = postgres://u:p@db.real-corp.com/x") == ["unlisted_host"]      # leak-ok
    assert LC.findings("remote git@gitlab.real-corp.com:grp/repo.git") == ["unlisted_host"]      # leak-ok
    assert LC.findings("https://www.example.com/ and git@x.test:a/b.git") == []


def test_every_commit_is_scanned_whatever_the_diff_settings(tmp_path, monkeypatch):
    def g(*args):
        subprocess.run(["git", "-C", str(tmp_path), *args], check=True, capture_output=True)
    g("init", "-q")
    for k, v in (("user.email", "t@x.test"), ("user.name", "t"), ("commit.gpgsign", "false"), ("core.hooksPath", str(tmp_path / "no-hooks")),
                 ("diff.noprefix", "true"), ("diff.mnemonicPrefix", "true")):      # prefix settings that once hid every path
        g("config", k, v)
    (tmp_path / "a.txt").write_text("start\n")
    g("add", ".")
    g("commit", "-qm", "base")
    g("tag", "base")
    f = tmp_path / "café.md"      # a non-ASCII name git would quote
    f.write_text("++ b/lookalike\nx see /Users/someone/x\n", encoding="utf-8")      # leak-ok: a "+++ b/..." content line first, then a leak after a U+2028
    (tmp_path / "doc.md").write_text("bin\x00 see /Users/someone/y\n", encoding="utf-8")      # leak-ok: a NUL byte must not make it "binary"
    g("add", ".")
    g("commit", "-qm", "add")
    g("checkout", "-qb", "side")      # a leak that only a merge's conflict fix adds
    (tmp_path / "a.txt").write_text("side\n")
    g("commit", "-qam", "side")
    g("checkout", "-q", "-")
    (tmp_path / "a.txt").write_text("main\n")
    g("commit", "-qam", "main")
    subprocess.run(["git", "-C", str(tmp_path), "merge", "-q", "side"], capture_output=True)      # conflicts on a.txt
    (tmp_path / "a.txt").write_text("merged /Users/someone/z\n")      # leak-ok
    g("commit", "-qam", "merge")
    f.write_text("clean\n", encoding="utf-8")      # removed again: the net diff is clean, the first commit is not
    g("add", ".")
    g("commit", "-qm", "remove")
    monkeypatch.chdir(tmp_path)
    hits = sorted({(name.split(":", 1)[1], k) for name, _, t in LC.added_lines("base") for k in LC.findings(t)})
    assert hits == [("a.txt", "home_path"), ("café.md", "home_path"), ("doc.md", "home_path")]
    assert LC.main(["leak_check.py", "base"]) == 1
