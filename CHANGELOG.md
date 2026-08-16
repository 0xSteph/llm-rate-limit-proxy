# Changelog

Notable changes, newest first. Versions follow [semver](https://semver.org).

## 0.2.0

First public release.

### Added

- **Anthropic protocol support.** A provider now declares whether it speaks
  `openai` or `anthropic`, and clients are authenticated by either
  `Authorization: Bearer` or `x-api-key`. Claude Code and other Anthropic-native
  clients work by pointing `ANTHROPIC_BASE_URL` at the proxy.

  Bodies are forwarded unchanged rather than translated, so a request is only
  routed to a provider speaking its own shape and is refused with `503` when
  none does. Both protocols can run behind one endpoint and one client key, with
  `/v1/models` merging their catalogs.

  Accounting follows each protocol: Anthropic's `input_tokens`/`output_tokens`
  are read alongside OpenAI's `prompt_tokens`/`completion_tokens`, including the
  nesting Anthropic uses when streaming, and truncation counts both `length` and
  `max_tokens`.
- Dual MIT OR Apache-2.0 licensing
- A savings view backed by a persisted usage ledger, priced at configurable
  per-model rates
- Context windows learned from providers that refuse over-long requests, then
  published through `/v1/models` and `/v1/props` so clients stop guessing
- Source-address allowlist, managed through the settings API
- One-line installer: checksum-verified binary and a hardened systemd unit
- Container images on GHCR, and a native Windows binary on each release
- `CONTRIBUTING.md` and `SECURITY.md`

### Fixed

- An upstream returning an empty `200` is now reported as an honest `400`
  rather than passed through as a success
- Generation time is measured across the whole buffered exchange
- `529` and `408` are retried; queue wait is recorded for streaming requests
