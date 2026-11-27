"""Leak check before publishing: scans what a push would publish (the lines each commit adds, and commit messages with author names, BASE..HEAD).

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

RESERVED_SUFFIXES = (".example", ".test", ".invalid", ".localhost", ".example.com", ".example.org", ".example.net")      # leading dot: "counterexample.com" is real
ALLOWED_HOSTS = {"api.anthropic.com", "webrisk.googleapis.com", "github.com", "www.wikipedia.org", "claude.ai", "claude.com"}
URL = re.compile(r"\b[a-z][a-z0-9+.-]*://(?:[^\s/@\"']*@)?([A-Za-z0-9.\-\[\]:]+)", re.I)      # any scheme (https, ssh, postgres...), host after any user:password@
SCP = re.compile(r"\bgit@([A-Za-z0-9.-]+):")      # git@host:group/repo.git
CHECKS = (
    ("home_path", re.compile(r"/(?:Users|home)/[A-Za-z0-9._-]+")),
    ("api_key", re.compile(r"sk-ant-[A-Za-z0-9_-]{8,}|\bBearer\s+[A-Za-z0-9._-]{20,}|\bAIza[0-9A-Za-z_-]{35}|\bAKIA[0-9A-Z]{16}\b"
                           r"|\bgh[pousr]_[A-Za-z0-9]{36}|\bglpat-[A-Za-z0-9_-]{20}")),      # Anthropic, bearer, Google, AWS, GitHub, GitLab
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
    if any(not host_ok(m.group(1)) for rx in (URL, SCP) for m in rx.finditer(text)):
        out.append("unlisted_host")
    return out


def git(*args):
    """git output as text whatever the user's diff settings or the file encodings (bytes that are not UTF-8 are replaced, not fatal)."""
    return subprocess.run(["git", "-c", "core.quotepath=off", *args], capture_output=True, check=True).stdout.decode("utf-8", "replace")


def added_lines(base):
    """(commit:file, line number, text) for every line ANY commit in BASE..HEAD adds: a push publishes each commit, not only the net diff."""
    # -m: merges too (a conflict fix exists in no other commit); --text --no-textconv: a "-diff" attribute or a NUL byte cannot turn a file into "Binary files differ"
    log = git("log", "-p", "-m", "--text", "--no-textconv", "-U0", "--no-color", "--no-ext-diff", "--src-prefix=a/", "--dst-prefix=b/",
              "--format=commit %h", base + "..HEAD")
    commit, path, n, header = "", None, 0, False
    for line in log.split("\n"):      # not splitlines(): it also breaks on U+2028, \x0c and others, hiding the rest of a line
        if line.startswith("commit "):      # no header or content line starts this way; a hunk-less file change leaves header set
            commit, header = line[7:], False
        elif line.startswith("diff --git "):
            path, header = None, True      # header lines until the first @@: a content line "+++ x" is not a header
        elif header and line.startswith("+++ "):
            p = line[4:].strip('"')
            path = p[2:] if p.startswith("b/") else None      # "/dev/null" for a deleted file
        elif line.startswith("@@"):
            header, n = False, int(re.search(r"\+(\d+)", line).group(1))
        elif not header and line.startswith("+") and path:
            yield "%s:%s" % (commit, path), n, line[1:]
            n += 1


def main(argv):
    base = argv[1] if len(argv) > 1 else "origin/main"
    words = private_words()
    try:
        hits = [(f, n, k) for f, n, t in added_lines(base) for k in findings(t)]
        log = git("log", "--format=%h %an %ae %cn %ce%n%B", base + "..HEAD")      # names and emails too: private words can sit there
    except subprocess.CalledProcessError:
        print("git error (is BASE a known commit?)")
        return 2
    hits += [("commit message", i + 1, k) for i, t in enumerate(log.split("\n")) for k in findings(t)]
    for f, n, k in hits:
        print("LEAK %s:%d %s" % (f, n, k))
    print("leak check: %d finding(s) in %s..HEAD (every commit; %d private word(s) set%s)" % (
        len(hits), base, len(words), "" if words else " - set LEAK_CHECK_PRIVATE_WORDS"))
    return 1 if hits else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
