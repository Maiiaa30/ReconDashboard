# Security policy

## Authorized use only

Recon Dashboard is **offensive security tooling**. Run it **only** against systems
you own or are **explicitly authorized in writing** to test. Unauthorized
scanning, fuzzing, or exploitation is illegal in most jurisdictions. Active/loud
modules are gated behind an explicit per-domain `active_authorized` flag, an
engagement scope, and an authorization window **by design** — those gates are
safeguards, not suggestions. You alone are responsible for how you use this
software. See the [disclaimer](./README.md#-disclaimer).

## Reporting a vulnerability

If you find a security issue in Recon Dashboard itself (not in a target you are
testing), please report it **privately** — do not open a public issue, and do not
include a working exploit or step-by-step extraction path in a public channel.

- Preferred: open a **GitHub private security advisory**
  (repository → Security → *Report a vulnerability*).
- Include: affected version/commit, a description of the problem class, impact,
  and the minimal information needed to reproduce it.

Please give a reasonable window to investigate and fix before any public
disclosure. This is a single-maintainer project run in spare time, so response is
best-effort.

## Scope

In scope: the dashboard's own code — auth/session handling, the SSRF guard and
target-facing HTTP client, active-scan gating and scope enforcement, the capture
ingest, backup encryption, and the production deployment topology.

Out of scope: findings the tool produces about *your authorized targets* (that is
its job), and anything that requires already having the operator's session or
host access (this is a single-operator app meant to live behind Tailscale, never
exposed to the public internet).

## Deployment expectations

- Run behind **Tailscale** on a private VM; never expose the port publicly.
- Set a real `ADMIN_PASSWORD` and a 32+ char `SESSION_SECRET` (the server refuses
  to boot otherwise), and enable **TOTP 2FA**.
- Use the production stack (`docker-compose.prod.yml`) with `TRUSTED_ORIGINS` set;
  see [`docs/production.md`](./docs/production.md).
- Keep an **encrypted backup off-box**.

The enforced-in-code security rails are listed in the
[README](./README.md#-security-ground-rules).
