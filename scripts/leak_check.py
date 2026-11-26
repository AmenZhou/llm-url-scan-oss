"""Leak check before publishing: scans what a push would add (added diff lines and commit messages, BASE..HEAD).

Usage: python scripts/leak_check.py [BASE]      (default BASE: origin/main)
Flags: web addresses whose host is not a reserved test name or on ALLOWED_HOSTS, home-folder paths, key-like
strings, private key blocks, and the words in LEAK_CHECK_PRIVATE_WORDS (comma list, e.g. names of datasets whose
results stay private; kept out of this public file on purpose). Prints place and kind only, never
the matching text, so the output itself is safe to share. Exit 0 clean, 1 findings, 2 git error.
Accept a reviewed line by putting the marker `leak-ok` on it, best with a short reason (`# leak-ok: public API`).
"""
import os
import re
import subprocess
import sys

RESERVED_SUFFIXES = (".example", ".test", ".invalid", ".localhost", "example.com", "example.org", "example.net")
ALLOWED_HOSTS = {"api.anthropic.com", "webrisk.googleapis.com", "github.com", "www.wikipedia.org", "claude.ai", "claude.com"}
URL = re.compile(r"\bhttps?://(?:[^\s/@\"']*@)?([A-Za-z0-9.\-\[\]:]+)", re.I)      # host after any user:password@
CHECKS = (
    ("home_path", re.compile(r"/(?:Users|home)/[A-Za-z0-9._-]+")),
    ("api_key", re.compile(r"sk-ant-[A-Za-z0-9_-]{8,}|\bBearer\s+[A-Za-z0-9._-]{20,}")),
    ("private_key", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
)


def private_words():
    return [w.strip().lower() for w in os.environ.get("LEAK_CHECK_PRIVATE_WORDS", "").split(",") if w.strip()]


def host_ok(host):
    """Reserved or allowed name, a name with no dot (not public), or an IP literal."""
    if host.startswith("["):
        return True
    h = host.lower().split(":")[0].rstrip(".")
    return ("." not in h or re.fullmatch(r"[\d.]+", h) is not None or h in ALLOWED_HOSTS
            or h.endswith(RESERVED_SUFFIXES) or h in {s.lstrip(".") for s in RESERVED_SUFFIXES})


def findings(text):
    """Kinds of leak found in one line of text."""
    if "leak-ok" in text:
        return []
    out = [kind for kind, rx in CHECKS if rx.search(text)]
    if any(w in text.lower() for w in private_words()):
        out.append("private_word")
    if any(not host_ok(m.group(1)) for m in URL.finditer(text)):
        out.append("unlisted_host")
    return out


def added_lines(base):
    """(file, line number, text) for every line BASE..HEAD adds."""
    diff = subprocess.run(["git", "diff", "-U0", "--no-color", base + "..HEAD"], capture_output=True, text=True, check=True).stdout
    path, n = None, 0
    for line in diff.splitlines():
        if line.startswith("+++ "):
            path = line[6:] if line.startswith("+++ b/") else None
        elif line.startswith("@@"):
            n = int(re.search(r"\+(\d+)", line).group(1))
        elif line.startswith("+") and path:
            yield path, n, line[1:]
            n += 1


def main(argv):
    base = argv[1] if len(argv) > 1 else "origin/main"
    try:
        hits = [(f, n, k) for f, n, t in added_lines(base) for k in findings(t)]
        log = subprocess.run(["git", "log", "--format=%h %B", base + "..HEAD"], capture_output=True, text=True, check=True).stdout
    except subprocess.CalledProcessError:
        print("git error (is BASE a known commit?)")
        return 2
    hits += [("commit message", i + 1, k) for i, t in enumerate(log.splitlines()) for k in findings(t)]
    for f, n, k in hits:
        print("LEAK %s:%d %s" % (f, n, k))
    print("leak check: %d finding(s) in %s..HEAD" % (len(hits), base))
    return 1 if hits else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
