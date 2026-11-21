"""Compose stack tests (marker `stack`; skipped by default). Run:  .venv/bin/python -m pytest -q -m stack

Brings the test stack up (docker-compose.yml + docker-compose.test.yml: local fixture pages, proxy in its TEST profile with a one-entry allowlist, the API in
test mode with a fake judge and a fake Web Risk) and takes it down at the end (set LLMURL_STACK_KEEP=1 to leave it up). Data dir and fake key files live in a
fresh folder under .scratch/. No real website, no key, no Anthropic or Google call: every page is served by the fixture container.
"""
import json
import os
import re
import secrets
import subprocess
import time
import urllib.request
from pathlib import Path

import pytest

from llm_url_scan.keys import init_secrets

pytestmark = pytest.mark.stack
ROOT = Path(__file__).resolve().parent.parent
PORT = "18800"
FX = "http://fx.example:8080"
WORKER_SCRIPT = ("import json,sys,urllib.request as u\n"
                 "t=open('/run/worker/worker_token').read().strip()\n"
                 "r=u.build_opener(u.ProxyHandler({})).open(u.Request('http://10.80.3.11:7100/'+sys.argv[1],"
                 "(json.dumps({'url':sys.argv[2]}).encode() if len(sys.argv)>2 else None),{'Authorization':'Bearer '+t}),timeout=150)\n"
                 "print(r.read().decode())\n")
CONNECT_SCRIPT = ("import socket,sys\n"
                  "for a in sys.argv[1:]:\n"
                  "    h,p=a.rsplit(':',1)\n"
                  "    s=socket.socket(); s.settimeout(3)\n"
                  "    print(a, 'CONNECTED' if s.connect_ex((h,int(p)))==0 else 'refused')\n"
                  "for n in ('example.com','host.docker.internal'):\n"
                  "    try:\n"
                  "        socket.getaddrinfo(n,80); print(n,'RESOLVED')\n"
                  "    except OSError:\n"
                  "        print(n,'no-resolve')\n")


class Stack:
    def __init__(self, tmp):
        self.data = tmp / "data"
        init_secrets(self.data)
        (tmp / "anthropic.env").write_text("LLMURL_ANTHROPIC_API_KEY=fake-not-a-key-0000\n")      # fake values: test mode never reads them, the mount just needs a file
        (tmp / "webrisk.env").write_text("LLMURL_WEBRISK_API_KEY=fake-not-a-key-0000\n")
        self.env = dict(os.environ, LLMURL_DATA_DIR=str(self.data), LLMURL_ANTHROPIC_KEY_FILE=str(tmp / "anthropic.env"), LLMURL_WEBRISK_KEY_FILE=str(tmp / "webrisk.env"),
                        LLMURL_PUBLISH_PORT=PORT, LLMURL_SALT_VERSION="1")
        for k in [k for k in self.env if k.startswith("ANTHROPIC_") or "PROXY" in k.upper()]:
            del self.env[k]
        self.token = (self.data / "secrets" / "caller_token_owner").read_text().strip()

    def compose(self, *args, check=True, timeout=600):
        r = subprocess.run(["docker", "compose", "-f", "docker-compose.yml", "-f", "docker-compose.test.yml", *args], cwd=ROOT, env=self.env, capture_output=True,
                           text=True, timeout=timeout)
        if check and r.returncode != 0:
            raise AssertionError("compose %s failed (%d)\n%s" % (args[0], r.returncode, (r.stdout + r.stderr)[-1200:]))
        return r

    def cexec(self, service, *cmd):
        return self.compose("exec", "-T", service, *cmd).stdout

    def worker(self, url):
        """Call the capture worker directly from inside its own container (it listens on api-net only)."""
        return json.loads(self.cexec("capture", "python3", "-c", WORKER_SCRIPT, "capture", url))

    def scan(self, url):
        req = urllib.request.Request("http://127.0.0.1:%s/v1/scan" % PORT, json.dumps({"url": url}).encode(), {"Authorization": "Bearer " + self.token})
        with urllib.request.urlopen(req, timeout=230) as r:
            return json.loads(r.read())

    def log(self):
        return [json.loads(l) for p in sorted(self.data.glob("scan-*.jsonl")) for l in p.read_text().splitlines()]


@pytest.fixture(scope="module")
def stack(tmp_path_factory):
    base = ROOT / ".scratch"
    base.mkdir(exist_ok=True)
    tmp = base / ("stack-%s-%s" % (time.strftime("%Y%m%d-%H%M%S"), secrets.token_hex(2)))
    tmp.mkdir()
    s = Stack(tmp)
    try:
        s.compose("up", "-d", "--build", "--wait", "--wait-timeout", "300")
        yield s
    finally:
        if os.environ.get("LLMURL_STACK_KEEP") != "1":
            s.compose("down", "-v", "--remove-orphans", check=False)


def test_docker_engine_version_floor():
    """The minimum engine version recorded in the README is 26.0."""
    v = subprocess.run(["docker", "version", "--format", "{{.Server.Version}}"], capture_output=True, text=True).stdout.strip()
    assert tuple(int(x) for x in re.match(r"(\d+)\.(\d+)", v).groups()) >= (26, 0), v


def test_direct_outbound_and_resolver_canary(stack):
    """Canary 1 and 3: from inside `capture` no direct connection works (public literal, metadata literal, egress-net, out-net, the api on both
    its addresses) and no name resolves through the container's own resolver."""
    out = stack.cexec("capture", "python3", "-c", CONNECT_SCRIPT, "1.1.1.1:443", "169.254.169.254:80", "10.80.2.2:3128", "10.80.4.10:8800", "10.80.3.10:8800",
                      "10.80.4.11:8800", "10.80.5.10:8080")
    assert "CONNECTED" not in out, out
    assert "RESOLVED" not in out and out.count("no-resolve") == 2, out


def test_api_listens_on_out_net_only(stack):
    """The api answers on its out-net address (the scheduler's route) and refuses on api-net, the network the browser's container shares."""
    assert stack.cexec("scheduler", "python", "-c", "import urllib.request as u; print(u.build_opener(u.ProxyHandler({})).open('http://10.80.4.10:8800/healthz', timeout=4).read().decode())").strip() == "ok"
    assert "CONNECTED" not in stack.cexec("capture", "python3", "-c", CONNECT_SCRIPT, "10.80.3.10:8800")


def test_sandbox_canary(stack):
    """Chromium's renderers run under seccomp with the sandbox on, and nothing started with --no-sandbox."""
    res = json.loads(stack.cexec("capture", "python3", "-c", WORKER_SCRIPT, "sandbox"))
    assert res["sandbox"] is True and res["renderers"] >= 1, res
    assert re.search(r"^CapEff:\s+0+$", stack.cexec("capture", "cat", "/proc/self/status"), re.M)      # no effective capability for the worker's user


def test_fetch_through_proxy_reaches_the_judge_path(stack):
    """A local harmless page, fetched through the proxy's test allowlist, arrives as page text at the (mocked) judge."""
    a = stack.scan(FX + "/ok")
    assert a["readable"] is True and a["unreadable_reason"] is None
    assert a["models_run"] == ["claude-haiku-5-5"] and a["decision"] == "pass" and a["reason"] == "pass_haiku"
    assert a["text_chars"] > 1000 and a["web_risk_d0"] == "negative"
    ev = stack.log()[-1]
    assert ev["event"] == "scan" and ev["readable"] is True and ev["forms"] >= 1 and ev["http_status_class"] == "2xx" and ev["tries"] == 1
    s = stack.scan(FX + "/short")      # a short page also goes to the second model (D1a)
    assert s["short"] is True and s["models_run"] == ["claude-haiku-5-5", "claude-sonnet-5-5"] and s["reason"] == "pass_sonnet_confirmed_short"
    r = stack.scan(FX + "/redirect")
    assert r["readable"] is True and stack.log()[-1]["redirects"] == 1


@pytest.mark.parametrize("path,reason,detail,rng", [
    ("/404", "gone", "http_404", None),
    ("/403", "site_blocked", "http_4xx", None),
])
def test_unreadable_site_reasons(stack, path, reason, detail, rng):
    a = stack.scan(FX + path)
    assert (a["readable"], a["unreadable_reason"], a["models_run"], a["decision"]) == (False, reason, [], "hold")
    ev = stack.log()[-1]
    assert (ev["unreadable_detail"], ev.get("range_class"), ev["reason"]) == (detail, rng, "unreadable_" + reason)


def test_unreadable_refused_by_our_proxy(stack):
    """A name that resolves to a private address is refused by the proxy (not allowlisted): proxy_refused with its range class."""
    a = stack.scan("http://refused.example:8080/ok")
    assert (a["readable"], a["unreadable_reason"], a["decision"], a["reason"]) == (False, "proxy_refused", "hold", "unreadable_proxy_refused")
    ev = stack.log()[-1]
    assert (ev["unreadable_detail"], ev["range_class"]) == ("resolved_blocked", "private")


def test_unreadable_other_timeout(stack):
    """A page that never answers: two tries, then an unreadable `other` hold (a 200 answer, not an error)."""
    a = stack.scan(FX + "/hang")
    assert (a["readable"], a["unreadable_reason"], a["decision"]) == (False, "other", "hold")
    ev = stack.log()[-1]
    assert (ev["unreadable_detail"], ev["tries"]) == ("deadline", 2)


@pytest.mark.parametrize("url,detail,rng", [
    ("http://127.0.0.1:7100/healthz", "literal_blocked", "loopback_or_unspecified"),      # the worker's own port, by loopback literal
    ("http://[::1]:7100/healthz", "literal_blocked", "loopback_or_unspecified"),
    ("http://localhost:7100/healthz", "name_blocked", None),                              # and by loopback name
    ("http://127.0.0.1:3128/__take", "literal_blocked", "loopback_or_unspecified"),       # a proxy slot port
    ("http://127.0.0.1:3129/__take", "literal_blocked", "loopback_or_unspecified"),
    ("http://169.254.169.254/latest/meta-data/", "literal_blocked", "link_local_or_metadata"),
    ("http://10.80.3.10:8800/healthz", "literal_blocked", "private"),                     # the api
    ("http://10.80.4.10:8800/healthz", "literal_blocked", "private"),
    ("http://10.80.1.2:3128/__take", "literal_blocked", "private"),                       # the proxy
    ("http://10.0.0.5/", "literal_blocked", "private"),
    ("http://host.docker.internal/", "name_blocked", None),                               # the host-gateway name
    ("http://refused.example:8080/ok", "resolved_blocked", "private"),                    # a public-looking name that resolves to a private address
])
def test_internal_targets_are_refused_by_the_proxy(stack, url, detail, rng):
    """Canary 4 and the loopback canary: through the browser each internal target class ends as a refused capture, with the proxy's reason and range class."""
    r = stack.worker(url)
    assert (r["readable"], r["unreadable_reason"], r["unreadable_detail"], r["range_class"]) == (False, "proxy_refused", detail, rng), r
    assert r["sections"] == {}


def test_proxy_refuses_to_start_without_extra_cidrs():
    """Production profile without EGRESS_BLOCK_EXTRA_CIDRS (unset or empty) exits 2 at start."""
    for args in ([], ["-e", "EGRESS_BLOCK_EXTRA_CIDRS="]):
        r = subprocess.run(["docker", "run", "--rm", "--pull", "never", "--network", "none", "-e", "EGRESS_PROFILE=production", *args, "llm-url-scan-proxy:local"],
                           capture_output=True, text=True, timeout=60)
        assert r.returncode == 2 and "EGRESS_BLOCK_EXTRA_CIDRS is required" in r.stderr, (r.returncode, r.stderr)
    # and with the word none it starts (and is stopped by the timeout)
    r = subprocess.run(["docker", "run", "--rm", "--pull", "never", "--network", "none", "-e", "EGRESS_PROFILE=production", "-e", "EGRESS_BLOCK_EXTRA_CIDRS=none",
                        "--stop-timeout", "1", "llm-url-scan-proxy:local", "sh", "-c", "timeout 3 node /app/egress-proxy.mjs; echo exit=$?"], capture_output=True, text=True, timeout=60)
    assert '"event":"start"' in r.stdout and "exit=124" in r.stdout, r.stdout + r.stderr


def test_each_container_sees_only_its_own_secret_files(stack):
    """Secrets are separate files mounted only where needed: the scheduler has the private key and its token, the api the salt, the public key and the hashes."""
    ls = lambda svc: sorted(stack.cexec(svc, "ls", "/data/secrets").split())      # noqa: E731
    assert ls("api") == ["callers.json", "hid_salt.1", "recheck_public.key"]
    assert ls("scheduler") == ["caller_token_scheduler", "recheck_private.key"]
    assert "No such file" in stack.compose("exec", "-T", "capture", "ls", "/data", check=False).stderr
    assert stack.cexec("capture", "ls", "/run/worker").split() == ["worker_token"]
    assert stack.compose("exec", "-T", "scheduler", "ls", "/run/worker", check=False).returncode != 0      # the worker token is not in the scheduler
    assert stack.compose("ps", "--status", "running", "--services").stdout.split().count("scheduler") == 1


def test_no_address_or_page_text_in_any_container_output(stack):
    """After the cycles above (timeout, refusal, 404, 403, loopback attempts, redirect), the output of every service holds none of the test hosts,
    the page marker or the loopback literals; the data dir holds none either (outside the encrypted store)."""
    logs = stack.compose("logs", "--no-color", "api", "capture", "proxy", "scheduler").stdout
    for bad in ("fx.example", "refused.example", "ZEBRAQUILL", "127.0.0.1:7100", "169.254.169.254", "host.docker.internal", "/latest/meta-data", "Forbidden"):
        assert bad not in logs, bad
    for p in stack.data.rglob("*"):
        if p.is_file() and "secrets" not in p.parts and p.suffix not in (".sqlite",) and not p.name.startswith("recheck"):
            t = p.read_text(errors="ignore")
            assert "fx.example" not in t and "ZEBRAQUILL" not in t, p.name
    assert stack.log() and all(e["event"] in ("scan", "refusal", "breaker") for e in stack.log())
