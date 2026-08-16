# Security policy

## Reporting a vulnerability

Please report privately through GitHub's
[private vulnerability reporting](https://github.com/0xSteph/llm-rate-limit-proxy/security/advisories/new)
rather than opening a public issue.

Include what you found, how to reproduce it, and what an attacker gets out of
it. I'll acknowledge within a few days and keep you updated as it's worked.

## What is in scope

This process holds every upstream provider key you give it, so the things worth
reporting are roughly:

- Anything that reveals a provider key, a client key secret, or an operator
  password hash through an API, the console, logs, or metrics
- Authentication or authorisation bypass — reaching the data plane without a
  valid client key, reaching operator-only settings without a superuser session,
  or acting on another owner's client keys
- Session handling flaws: forgery, fixation, or a session outliving the password
  reset that should have ended it
- A panic or unbounded resource use reachable from untrusted input (request
  paths, bodies, upstream response headers, cookies, the config store)
- Anything that makes the proxy exceed a configured upstream rate limit, since
  correctness of pacing is the guarantee this project exists to provide

## What is out of scope

- Exposing the proxy to a hostile network on purpose. It binds loopback by
  default and terminates no TLS; `HOST=0.0.0.0` without a reverse proxy in front
  is a deployment choice, not a vulnerability.
- Anyone with write access to `DATA_DIR` or the ability to run code as the
  service user. That file holds live credentials at mode `0600`; the threat
  model assumes the host itself is trusted.
- Denial of service from a client that already holds a valid client key.
- Missing hardening that is documented as missing in the README's security
  posture section.

## Supported versions

The most recent release. This is a young project — please upgrade before
reporting, in case you've found something already fixed.
