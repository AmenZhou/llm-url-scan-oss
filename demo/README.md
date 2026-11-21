# Live local demo

A web page with ten cards. Each card is a made-up page; **Scan** sends it through the real service (real capture in the isolated browser, real Anthropic judge, real verdict) and shows the answer next to the outcome the page was designed for.

**Status: built and tested offline only (`tests/test_demo_server.py`). It has not been run live yet.** Whether the real judge matches each designed outcome is exactly what the first live run will show.

## What it costs and what it proves

- Every scan calls the real Anthropic API: about USD 0.01 each (a little more when the second model also runs; unreadable pages cost nothing). The run cap from `LLMURL_RUN_CAP_USD` / `LLMURL_RUN_START` applies.
- The designed outcomes are designs, not guarantees. Results on ten made-up pages say nothing about accuracy.

## The ten pages

Seven come from `tests/stack/fixtures.py` (`/ok`, `/short`, `/bank`, `/redirect`, `/404`, `/403`, `/hang`), three are new and made up with invented brands: a benign sign-in page (`/login`, should pass), a parcel-fee scam (`/parcel`, should hold) and a prize scam with hidden, off-screen and tiny text that tells the reviewer to answer benign (`/inject`, should still hold). The hidden text is the only difference that matters for the third one; whether the page-text step keeps it in front of the model is something only the live run shows.

## How it is wired

- `demo/server.py` (standard library only) listens on `127.0.0.1:8090`. The browser sends only a page id from a fixed list; the server maps it to the fixture address and calls `POST /v1/scan` with the owner token it reads from `<data dir>/secrets/caller_token_owner`. The token is in no response, log line or page. One scan at a time (409 otherwise). Host, Origin, Fetch Metadata and Content-Type are checked, the page gets a per-response nonce CSP, and logs hold only the route and the status code.
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
docker compose -f docker-compose.yml -f docker-compose.smoke.yml -f demo/docker-compose.demo.yml up -d --build --wait
.venv/bin/python demo/server.py --data-dir "$LLMURL_DATA_DIR"
```

Open <http://127.0.0.1:8090/>. Use `--port` to change the demo port and `--api` if you published the service on another port (default `http://127.0.0.1:8800`, set `LLMURL_PUBLISH_PORT` to change it).

## Stop

Press Ctrl-C in the terminal running `demo/server.py`, then:

```
docker compose -f docker-compose.yml -f docker-compose.smoke.yml -f demo/docker-compose.demo.yml down -v --remove-orphans
```

Delete `data/` yourself if you want the scan log and the sealed recheck store gone.
