# Changelog

Notable changes, newest first. Versions follow [semver](https://semver.org).

## 0.2.0

First public release.

### Renamed

- The project is now `llm-rate-limit-proxy`, previously `sluice`. This changes
  the binary, the crate, the systemd unit, the data directory, environment
  variables, Prometheus metric names, the session cookie, the deadline header,
  and the client key prefix.

  Upgrading from a `sluice` install is a manual step: copy
  `/var/lib/sluice/config.json` to `/var/lib/llm-rate-limit-proxy/config.json`,
  then re-run the installer. Client keys minted before the rename keep working —
  only the prefix on newly minted keys changes. Prometheus dashboards and alert
  rules need `sluice_*` renamed to `llm_rate_limit_proxy_*`.

### Added

- Dual MIT OR Apache-2.0 licensing
- A savings view backed by a persisted usage ledger, priced at configurable
  per-model rates
- Context windows learned from providers that refuse over-long requests, then
  published through `/v1/models` and `/v1/props` so clients stop guessing
- Source-address allowlist, managed through the settings API
- `CONTRIBUTING.md` and `SECURITY.md`

### Fixed

- An upstream returning an empty `200` is now reported as an honest `400`
  rather than passed through as a success
- Generation time is measured across the whole buffered exchange
- `529` and `408` are retried; queue wait is recorded for streaming requests

## 0.1.1

- Native Windows binary published on each release
- One-line installer with checksum verification and a hardened systemd unit
- Container images published to GHCR on every push and tag

## 0.1.0

Initial tagged release.
