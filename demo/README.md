# Live local demo

A web page with an input box for pasting a URL, a list of clickable sample URLs, and ten cards. Each card is a made-up page; **Scan** (or a click on its sample URL) sends it through the real service (real capture in the isolated browser, real Anthropic judge, real verdict) and shows the answer next to the outcome the page was designed for.

**Status: tested offline (`tests/test_demo_server.py`) and run live on 2026-11-21 in sample mode.** All ten cards answered through the real service. The first run showed the real judge does not always match a design: the long ordinary page (`/ok`) was held by both models under R1, although it was designed to pass. The URL input box and the `--open-urls` mode were added after that run; only sample mode has been run live.

## Two modes

- **Sample mode (default).** The input box and the sample links accept only the ten made-up addresses (shown on the page). Any other URL answers "not allowed in this mode". The demo proxy can reach only those made-up hosts, so nothing on the internet is fetched.
- **Open mode (`--open-urls`).** Any http or https URL pasted into the box is scanned. This needs the normal stack, not the demo allowlist (see "Open mode" below). The full address goes to Anthropic and to Google Web Risk, and the live page is fetched in the isolated browser. The made-up samples are replaced by two harmless real ones.

## What it costs and what it proves

- Every scan calls the real Anthropic API: about USD 0.01 each (a little more when the second model also runs; unreadable pages cost nothing). The run cap from `LLMURL_RUN_CAP_USD` / `LLMURL_RUN_START` applies.
- The designed outcomes are designs, not guarantees. Results on ten made-up pages say nothing about accuracy.

## The ten pages

Seven come from `tests/stack/fixtures.py` (`/ok`, `/short`, `/bank`, `/redirect`, `/404`, `/403`, `/hang`), three are new and made up with invented brands: a benign sign-in page (`/login`, should pass), a parcel-fee scam (`/parcel`, should hold) and a prize scam with hidden, off-screen and tiny text that tells the reviewer to answer benign (`/inject`, should still hold). The hidden text is the only difference that matters for the third one; whether the page-text step keeps it in front of the model is something only the live run shows.

## How it is wired

- `demo/server.py` (standard library only) listens on `127.0.0.1:8090`. The browser sends either a page id from a fixed list or a URL. A URL is accepted only if it is one of the ten made-up addresses, unless `--open-urls` is set (then any valid http or https URL, up to 2,048 characters, without user:password). The server calls `POST /v1/scan` with the owner token it reads from `<data dir>/secrets/caller_token_owner`. The token is in no response, log line or page, and a URL you paste is never echoed back or logged. One scan at a time (409 otherwise). Host, Origin, Fetch Metadata and Content-Type are checked, the page gets a per-response nonce CSP, and logs hold only the route and the status code.
- `demo/docker-compose.demo.yml` adds three host names (`quillfisher.example`, `parcelhop.example`, `quillfisher-rewards.example`) as aliases of the fixture container and points the proxy at `demo/allowlist.json`. Same mechanism as the test profile: the proxy can reach those made-up names and nothing else. The names exist only on the internal `fixture-net`.
- Nothing in the production defaults changes. Test mode stays off, so the real judge runs.

## Subnets: do not run next to another stack

This stack uses the `10.80.0.0/16` Docker subnets, like the main compose file and the stack tests. Do not start it while any other stack that uses those subnets is running, and do not run it at the same time as `pytest -m stack`.

## Start

From the repository root, with your own keys (never committed; `secrets/` and `*.env` are git-ignored):

```
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
export LLMURL_DATA_DIR=$PWD/data
.venv/bin/python -m llm_url_scan init
mkdir -p secrets
umask 077
echo 'LLMURL_ANTHROPIC_API_KEY=...' > secrets/anthropic.env
echo 'LLMURL_WEBRISK_API_KEY=...'   > secrets/webrisk.env
export LLMURL_SALT_VERSION=1
export LLMURL_RUN_CAP_USD=1 LLMURL_RUN_START=$(date +%Y-%m-%d)   # optional spend cap for this run
docker compose -p llm-url-scan-demo -f docker-compose.yml -f docker-compose.smoke.yml -f demo/docker-compose.demo.yml up -d --build --wait
.venv/bin/python demo/server.py --data-dir "$LLMURL_DATA_DIR"
```

If every scan answers "service_refused / capture_unavailable" (HTTP 503), run `docker compose -p llm-url-scan-demo restart capture api`. `token-init` writes a new worker token on every `up`, so a second `up` leaves the running capture worker holding the old one (it answers 401 to the API).

Open <http://127.0.0.1:8090/>. Use `--port` to change the demo port and `--api` if you published the service on another port (default `http://127.0.0.1:8800`, set `LLMURL_PUBLISH_PORT` to change it).

## Open mode (real URLs)

Not run live yet. The demo overlay and the smoke overlay point the proxy at the made-up hosts only, so for real URLs start the normal stack and add the flag:

```
export EGRESS_BLOCK_EXTRA_CIDRS="10.0.0.0/8,172.16.0.0/12,192.168.0.0/16"      # your VPN and company ranges, or the word none
docker compose -p llm-url-scan-demo up -d --build --wait
.venv/bin/python demo/server.py --data-dir "$LLMURL_DATA_DIR" --open-urls
```

Use a real Web Risk key here (the demo placeholder makes Web Risk answer "error", and the key file must still be 8 or more characters). Stop it as below, with only the main compose file in the `down` command.

## Stop

Press Ctrl-C in the terminal running `demo/server.py`, then:

```
docker compose -p llm-url-scan-demo -f docker-compose.yml -f docker-compose.smoke.yml -f demo/docker-compose.demo.yml down -v --remove-orphans
```

Delete `data/` yourself if you want the scan log and the sealed recheck store gone.
