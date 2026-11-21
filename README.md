# llm-url-scan

A small HTTP service that takes one URL, opens the page in an isolated browser, asks an LLM whether it looks like phishing, and answers `pass` or `hold` with a reason code. It also logs the Google Web Risk verdict for the same URL (on day 0 and again on day 7) so you can measure the judge against an independent signal.

**Advisory only.** The answer blocks nothing, and the response says `"advisory": true`. Before any caller enforces the answer, a `pass` that carries the `truncated` or `injection_text` flag should be turned into a `hold` (a rule you add at that time, with tests).

## How a scan works

1. **Capture.** A Playwright Chromium worker, in a container with the browser sandbox on and every Linux capability dropped, loads the URL. Its only way out is a deny-by-default **egress proxy** that refuses loopback, private, link-local, metadata and carrier-grade-NAT addresses, internal names, and names that *resolve* to such addresses.
2. **Page text.** The worker turns the page into a small, capped text form: title, visible text, forms (fields, actions), buttons, redirect hops and a page state (`ok`, `parked`, `bot-wall`, `http-404`, `dns`, ...).
3. **Judge (rule "D1a").** D1a is the routing rule: Haiku judges every readable page; Sonnet re-judges when Haiku holds, cannot tell, fails, or passes a page of 1,000 characters or fewer; unreadable pages are held. A Sonnet cannot-tell or failure is a hold. The prompt is `llm_url_scan/prompts/prompt-v3.md`; the service refuses to start if its hash changes.
4. **Unreadable pages are held.** If the page cannot be read (blocked, gone, refused by the proxy, timed out), the answer is `hold`, no model runs, and the reason says why.
5. **Web Risk, logged only.** The URL is checked against Google Web Risk on day 0 and day 7. It never changes the answer.
6. **Recheck.** Pages held as unreadable or as Sonnet cannot-tell get one more capture and judgement about six hours later. It is logged only; the first answer stands.

The model sees the scheme, host and path plus the *length* of the query string, never the query itself. Web Risk receives the full address.

## Privacy and logging

- Logs are counts and fixed words only: no URL, host, page text, brand string or error message is ever written. Ids in logs are salted hashes. Every log line passes a leak guard (`llm_url_scan/logs.py`), and `tests/test_leak.py` checks it.
- The addresses of pages that still need a recheck are kept in an encrypted store (public-key sealed; only the scheduler holds the private key) and hard-deleted after 10 days.
- URLs you submit are sent to Anthropic (the model sees the query-less address and the page text) and to Google (Web Risk). Make sure that is acceptable for the URLs you scan, and that you may use any feed you scan from.

## Quick start

Python 3.12 or newer, Docker engine 26 or newer, Node 24 (only to run the proxy tests outside Docker).

```
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
.venv/bin/python -m pytest -q                 # network-free; tests marked `stack` or `live` are skipped
```

Create the data directory and secrets, then put your API keys in files:

```
export LLMURL_DATA_DIR=./data
.venv/bin/python -m llm_url_scan init         # creates the data dir, a salt, a recheck key pair and caller tokens (mode 0600)
mkdir -p secrets
umask 077                                      # the key files below are created readable by you only
echo 'LLMURL_ANTHROPIC_API_KEY=...' > secrets/anthropic.env
echo 'LLMURL_WEBRISK_API_KEY=...'   > secrets/webrisk.env
```

Start the stack. The proxy refuses to start unless you say which extra ranges to block (your VPN and company ranges, a comma list of CIDRs) or explicitly say `none`:

```
export EGRESS_BLOCK_EXTRA_CIDRS="10.0.0.0/8,172.16.0.0/12,192.168.0.0/16"
docker compose up -d --build
docker compose ps                              # all healthy
curl -s -X POST http://127.0.0.1:8800/v1/scan \
  -H "Authorization: Bearer $(cat ./data/secrets/caller_token_owner)" \
  -H 'Content-Type: application/json' -d '{"url": "https://example.com/"}'
docker compose down
```

The API is published on `127.0.0.1:8800` only. `GET /healthz` and `GET /v1/status` (authenticated) exist; `/docs`, `/redoc` and `/openapi.json` are off. Errors are `{"error": "<code>"}` and never echo the input.

Other commands: `python -m llm_url_scan status`, `resume <kind>` (lift a circuit breaker; only the owner token), `report` (weekly counts), `recheck-loop` (the scheduler).

## Configuration

Environment variables: `LLMURL_DATA_DIR`, `LLMURL_ANTHROPIC_KEY_FILE`, `LLMURL_ANTHROPIC_KEY_VAR`, `LLMURL_WEBRISK_KEY_FILE`, `LLMURL_DAILY_CAP_USD` (default 2), `LLMURL_TOTAL_CAP_USD` (default 20), `LLMURL_RUN_CAP_USD` with `LLMURL_RUN_START`, `LLMURL_WEBRISK_DAILY_CEILING`, `LLMURL_HOST`, `LLMURL_PORT`, `LLMURL_PUBLISH_PORT`, `LLMURL_SALT_VERSION`, `LLMURL_UID` / `LLMURL_GID`. For the proxy: `EGRESS_BLOCK_EXTRA_CIDRS` (required), `EGRESS_DNS_SERVERS` and `EGRESS_ALLOWED_PORTS` (optional).

Spend caps and circuit breakers live in `llm_url_scan/ledger.py`. The mean-cost breaker trips when the rolling mean cost per judged scan exceeds 1.25 times `PLAN_MEAN`; set `PLAN_MEAN` to your own traffic mix (a phishing-only sample costs more than a mixed one because almost every page reaches the second model).

Each secret is a separate file mounted read-only only into the containers that need it: the API gets the salt, the public recheck key, the caller hashes and both API keys; the scheduler gets the private recheck key, its own token and the Web Risk key; the capture worker gets only its worker token.

## Tests

- `pytest -q`: the network-free suite (mocked Anthropic, Web Risk and capture clients).
- `pytest -q -m stack`: builds and starts a test stack with local fixture pages and a proxy test profile, runs the isolation canaries, and tears it down. It uses the `10.80.0.0/16` Docker subnets; do not run it next to another stack that uses them.
- `node --test proxy/egress-proxy.test.mjs`: the proxy's own suite.

**Status:** the network-free suite (339 tests, 23 of them for the demo server and its fixtures) and the proxy suite (126 tests) pass on this version. The `-m stack` suite, which runs the real containers and the isolation canaries, has not yet been re-run on this version. Run it yourself before relying on the isolation.

## Demo

`demo/` holds a live local demo page: ten made-up pages, each scanned by the real service with the real judge (about USD 0.01 per scan), shown next to the outcome it was designed for. See `demo/README.md` for the commands. It uses the same `10.80.0.0/16` subnets as the stack tests. It has been built and tested offline only; it has not been run live yet.

## Reading the logs and reports

False holds are an upper bound: nobody labels pages, so a hold that Web Risk does not list is *unconfirmed*, not false. Web Risk positive means the address is listed; negative does not mean safe. Agreement with Web Risk is consistent, not independent. Unreadable pages are held by policy and counted apart. The weekly report prints no percentage for a group under 30 pages.

## Known gaps

- Recheck key-pair rotation does not exist; the pair made by `init` is kept.
- Running `init` again adds a salt version, but compose mounts `hid_salt.${LLMURL_SALT_VERSION:-1}`; set `LLMURL_SALT_VERSION` after a rotation.
- A 504 deadline keeps the full spend reservation even when no model ran.
- Web Risk is called in parallel with capture, so an address can reach Google on a call that capture then refuses.
- `/internal/recheck6` trusts the hash id the scheduler sends.
- Every refusal (401 included) writes one log line; compose has no `restart:` policy.
- The day-7 Web Risk check runs from day 7 to day 8.
- Judge quality has been measured only on small samples; treat it as unproven until you measure it on your own traffic.

## Layout

`llm_url_scan/`: `judge` (message builder, parser, one model call), `decide` (the D1a table), `patterns`, `webrisk`, `logs` (counts-only writer and leak guard), `store` (salted ids, sealed address store), `keys`, `ledger` (spend cap and breakers), `urlcheck` (URL validation and the no-DNS classifier), `capture` / `capture_worker` (client and worker), `pagetext`, `testmode`, `service` (pipeline), `app` (FastAPI), `cli`, `recheck`, `report`. `proxy/`: the egress proxy and its tests. `docker/`: Dockerfiles and the seccomp profile. `tests/`: pytest suites.

## Licence

Apache License 2.0, see `LICENSE` and `NOTICE`.
