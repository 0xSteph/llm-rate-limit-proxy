# Contributing

Thanks for looking. Issues and pull requests are both welcome.

## Getting set up

```sh
git clone https://github.com/0xSteph/llm-rate-limit-proxy
cd llm-rate-limit-proxy
cargo run --release
```

Then open `http://localhost:8000` and complete the setup wizard. The first
visitor claims the install, so this is a one-time step per `DATA_DIR`.

## Before you open a PR

Everything CI checks, you can run locally:

```sh
cargo fmt --all -- --check
cargo clippy --all-targets -- -D warnings
cargo test
cargo test --release --test load -- --ignored
```

The load test is the one that matters most for changes to pacing, queueing or
the key pool: it runs 100 concurrent clients against a mock upstream that
strictly enforces a rate window, and asserts the upstream saw **zero**
violations. If your change can make that fail, it is not ready.

## What a good change looks like

- **Tests come with it.** The end-to-end suite boots the real binary against a
  throwaway data directory, so a behavioural change is usually testable without
  mocking internals. Look at `tests/e2e.rs` for the pattern.
- **Parsers get property tests.** Anything that reads untrusted bytes — request
  paths and bodies, upstream headers, cookies, the config store — carries a
  proptest asserting it never panics and never falsely accepts. New parsers
  should too.
- **Comments explain why, not what.** The code says what it does. A comment
  earns its place by recording a constraint, a workaround, or a surprising
  invariant that the next reader would otherwise have to rediscover.
- **Metrics stay content-blind.** Counts, sizes, latencies and labels derived
  from them. Never message content, never prompts.

## Things worth knowing

- **Rate limiting is the whole product.** Changes that make pacing looser to
  gain throughput are usually the wrong trade. The guarantee is that the
  upstream never sees a violation; throughput is what is left over.
- **The proxy holds every provider key.** It binds loopback by default and
  terminates no TLS. Anything that widens its exposure needs to be a deliberate,
  documented choice rather than a convenient default.
- **Settings apply live.** There is no restart-to-apply path. New settings
  should follow the same rule.

## Reporting a bug

Include what you expected, what happened, and the smallest reproduction you can
manage. If it involves an upstream provider, the provider name and the status
code it returned are usually the two most useful facts.

For anything security-sensitive, see [SECURITY.md](SECURITY.md) instead — please
don't open a public issue.

## Licence

By contributing you agree that your contribution is dual licensed under MIT and
Apache-2.0, matching the project.
