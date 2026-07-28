# Sluice

A rate-limit-aware, multi-provider proxy for OpenAI-compatible LLM APIs.

Point your agent harness at one endpoint with one key. Sluice paces requests
across a pool of upstream API keys so the harness never sees a rate limit, fails
over when a key or a provider misbehaves, and reports what is actually happening
underneath.

## Why

Free and low tier LLM APIs cap requests per minute per key. When an agent harness
hits that cap the upstream returns 429 and most harnesses abort the task outright.
Sluice sits in between and makes the limit invisible: requests queue rather than
fail, and streaming clients are held open with SSE heartbeats while they wait.

It is not a way around anyone's terms of service. Each key is held to its own
limit; the proxy makes agents patient enough to live within the budget you
already have.

## What it does

**Pacing and routing**

- One lane per API key, each with an exact sliding-window limiter and a jitter
  margin so a boundary-timed request can't land inside the provider's window
- A single global FIFO queue across all clients — slots are granted in arrival
  order, so no client can starve another
- Conversations stick to one key via rendezvous hashing, keeping any upstream
  prefix cache warm. Adding or removing a key relocates only that key's share of
  conversations rather than remapping all of them
- Everything else takes the least-loaded lane, spreading concurrent work across
  keys instead of stacking it on the first one

**Resilience**

- Automatic failover across keys and across providers
- A rebuffed key is benched for as long as its `Retry-After` asks (clamped), so
  the next request doesn't rediscover the same wall
- A model-pressure governor for provider-side concurrency caps that key failover
  cannot relieve. Detection is behavioral — the same model rebuffed on two
  different keys within seconds — so it needs no knowledge of any provider's
  error wording
- Optional absolute request deadlines via `X-Sluice-Deadline-Ms`
- Bounded concurrency with load shedding

**Multi-provider**

- Several upstream providers behind one endpoint
- Virtual models: a name that resolves to an ordered list of concrete targets,
  tried in turn, so a request survives a provider outage
- `/v1/models` merges every provider's catalog with your virtual models and is
  served from cache, so catalog polls cost no rate budget

**Operations**

- Setup wizard, session auth, client API keys stored only as digests
- Runtime settings, all live with no restart: providers, provider keys, client
  keys, virtual models, operator accounts, and limits
- Content-blind metrics (counts, sizes, latencies — never message content),
  persisted snapshots for range views, and a dashboard
- `/api/pressure` reports models held back by provider-side limits, so a stalled
  agent is never mistaken for an idle proxy

## Running it

```sh
cargo run --release
```

Then open `http://localhost:8000/`. The first visitor claims the install: create
the admin account, add one provider key, and the wizard mints your first client
key. Point your harness at `http://localhost:8000/v1` with that key.

Until setup completes the data plane is closed and browsers are sent to the
wizard.

| Variable | Default | Purpose |
|---|---|---|
| `HOST` / `PORT` | `0.0.0.0` / `8000` | Bind address |
| `DATA_DIR` | `data` | Where the config store and history live |
| `TRUST_PROXY` | `false` | Trust `X-Forwarded-Proto`; marks the session cookie `Secure` |

Everything else is managed in Settings and applies live.

## Tests

```sh
cargo test                            # unit + end-to-end
cargo test --test load -- --ignored   # 100 concurrent clients, asserts zero
                                      # upstream rate violations
```

## Status

Working and tested, not yet packaged. No Docker image and no TLS termination —
put a reverse proxy in front for anything exposed. The settings API is complete;
the dashboard renders observability but not yet forms for every settings route,
so some changes are a `POST` rather than a click.
