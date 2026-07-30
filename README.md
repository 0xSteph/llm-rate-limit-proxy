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

## Install

**One line.** Downloads the right binary, verifies its checksum, installs a
hardened systemd service, and starts it:

```sh
curl -fsSL https://raw.githubusercontent.com/0xSteph/sluice/master/install.sh | sh
```

Then open `http://localhost:8000` and finish the wizard. Re-run the same command
to upgrade; your keys and settings are untouched.

While the repository is private, pass a token that can read it:

```sh
SLUICE_TOKEN=ghp_... curl -fsSL https://raw.githubusercontent.com/0xSteph/sluice/master/install.sh | sh
```

It binds loopback, runs as an unprivileged `sluice` user with no shell, stores
data in `/var/lib/sluice` at mode 0700, and the unit drops every capability.
Override with `SLUICE_PORT`, `SLUICE_HOST`, `SLUICE_DATA_DIR`.

**Container** — if you would rather not install anything:

```sh
docker run -d --name sluice \
  -p 127.0.0.1:8000:8000 \
  -v sluice-data:/data \
  ghcr.io/0xsteph/sluice:latest
```

Or with compose, which also applies the hardening (read-only root, no
capabilities, loopback publish):

```sh
docker compose up -d
```

**Binary** — attached to each release for `linux/amd64` and `linux/arm64`:

```sh
curl -fsSLO https://github.com/0xSteph/sluice/releases/latest/download/SHA256SUMS
curl -fsSLO https://github.com/0xSteph/sluice/releases/latest/download/sluice-VERSION-linux-amd64.tar.gz
sha256sum -c SHA256SUMS --ignore-missing
tar xzf sluice-*-linux-amd64.tar.gz && ./sluice-amd64
```

The binary is extracted from the published image rather than built separately,
so it is the same bytes that run in the container.

**From source:**

```sh
cargo run --release
```

Images are published on every push to `master` as `:edge`, and on a version tag
as `:1.2.3`, `:1.2` and `:latest`. `:edge` is whatever just landed; tags are the
statement that a commit is meant to be run.

Then open `http://localhost:8000/`. The first visitor claims the install: create
the admin account, add one provider key, and the wizard mints your first client
key. Point your harness at `http://localhost:8000/v1` with that key.

Until setup completes the data plane is closed and browsers are sent to the
wizard.

| Variable | Default | Purpose |
|---|---|---|
| `HOST` / `PORT` | `127.0.0.1` / `8000` | Bind address. Loopback by default — this process holds every provider key and terminates no TLS, so set `HOST=0.0.0.0` only behind a reverse proxy |
| `DATA_DIR` | `data` | Where the config store and history live |
| `TRUST_PROXY` | `false` | Trust `X-Forwarded-Proto`; marks the session cookie `Secure` |

Everything else is managed in Settings and applies live.

## Tests

```sh
cargo test                            # unit + end-to-end
cargo test --test load -- --ignored   # 100 concurrent clients, asserts zero
                                      # upstream rate violations
```

## Operations

### Monitoring

`GET /metrics` serves Prometheus text. It accepts either a console session or
HTTP Basic with any operator account, and answers `401` rather than redirecting,
because a scraper cannot follow a redirect into a login page.

```yaml
scrape_configs:
  - job_name: sluice
    basic_auth: { username: admin, password: your-password }
    static_configs: [{ targets: ["localhost:8000"] }]
```

`GET /health` needs no credentials and exposes nothing — it exists for load
balancers and container probes.

### Backup

Everything that matters is one file: `DATA_DIR/config.json`. It holds your
provider keys, the digests of every client key, operator password hashes,
aliases and settings. Lose it and you re-enter every key by hand.

```sh
install -m 600 /path/to/data/config.json /somewhere/safe/config.json
```

It is mode `0600` and contains live credentials — back it up somewhere with at
least the same protection as the machine it came from.

`history.jsonl` alongside it is metrics snapshots only. Losing it costs you the
range views and nothing else.

To restore, drop the file into an empty `DATA_DIR` and start. No import step and
no re-setup: the wizard stays closed because a superuser already exists.
Verified — a restored instance came back with all 13 lanes, the original
password, and previously minted client keys still working.

## Security posture

- Binds loopback by default. This process holds every provider key and
  terminates no TLS, so exposing it is a deliberate `HOST=` behind a reverse
  proxy.
- The container is a 6 MB `scratch` image — no shell, no package manager, no
  libc — running as an unprivileged uid with a read-only root filesystem and
  all capabilities dropped.
- Reconfiguring the server is administrator-only. Client keys are self-service
  but owner-scoped: you can retire your own, not someone else's.
- Sessions are bound to the password they were issued against, so a reset ends
  every live session for that account immediately.
- Client key secrets are stored only as SHA-256 digests and shown exactly once.
- CI runs fmt, clippy (`-D warnings`), tests, a release build, the load test,
  and a dependency audit on every push, plus the audit weekly.
- The parsers that read untrusted bytes — request paths and bodies, upstream
  headers, session cookies, the config store — carry property tests asserting
  they never panic and never falsely accept, on generated hostile input.

TLS is not built in — terminate it at a reverse proxy and set `TRUST_PROXY=true`
so the session cookie is marked `Secure`.

## Status

Working, tested, and packaged. The settings API is complete; the console
renders observability and settings forms, though not every route has a form yet.
