# Production runbook

How to run Recon Dashboard in production: a single-origin, compiled-frontend
deployment on a private VM reached **only over Tailscale**. It is never exposed to
the public internet and there is no public TLS/ACME by design.

See [`docker-compose.prod.yml`](../docker-compose.prod.yml) for the topology and
[the security ground rules](../README.md#-security-ground-rules) for the model.

## Topology

- **One origin, one port.** The frontend is built to static assets and served by
  the backend (`@fastify/static`) alongside the API. Only `3001` is published,
  reachable through the host's tailnet address.
- **`NODE_ENV=production`**, no read-write source bind mounts — the image is the
  artifact.
- **CSRF Origin check** enforced on state-changing session requests
  (`TRUSTED_ORIGINS`), on top of the `SameSite=strict` session cookie.
- **SQLite** lives in the `app-data` volume; the built SPA in the `spa-dist`
  volume (republished on every up).

## First deploy

1. Provision a small VM (Oracle Always Free / Hetzner / OVH) and join it to your
   tailnet. Do **not** open port 3001 to the public internet — only the tailnet.
2. Clone the repo and create `.env` from the example:
   ```bash
   git clone https://github.com/Maiiaa30/ReconDashboard.git
   cd ReconDashboard
   cp .env.example .env
   ```
3. Set at least these in `.env`:
   - `ADMIN_PASSWORD` — a real password (the server refuses to boot on the default).
   - `SESSION_SECRET` — 32+ random chars.
   - `TRUSTED_ORIGINS` — your tailnet app URL, e.g.
     `https://recon.<tailnet>.ts.net` (comma-separated for more than one).
   `STATIC_DIR` is set by the compose file — leave it blank in `.env`.
4. Bring it up:
   ```bash
   docker compose -f docker-compose.prod.yml up -d --build
   ```
   The `frontend-build` service compiles the SPA into the `spa-dist` volume and
   exits; the backend then boots, applies migrations, seeds the operator, and
   serves the whole app on `3001`.
5. Open `https://<host>.<tailnet>.ts.net:3001/` and log in. Enable TOTP 2FA from
   **Settings**.

## Health

- Liveness endpoint: `GET /api/health` → `{ "status": "ok" }` (public, unauthed).
- The compose service has a `healthcheck` hitting it; `docker compose -f
  docker-compose.prod.yml ps` shows `healthy` once boot completes (~40s grace for
  first-run migrations).
- Consolidated readiness (scanners, providers, DB, worker, queue, backup age) is
  in the **Readiness** page in the UI.

## Upgrade

```bash
git pull
docker compose -f docker-compose.prod.yml up -d --build
```

Migrations apply automatically on backend boot. The `spa-dist` volume is
repopulated by the rebuilt `frontend-build` service, so the UI updates too. Watch
`docker compose -f docker-compose.prod.yml logs -f backend` until it reports
listening and the healthcheck is green.

## Backup & restore

The database is the only stateful thing to protect. Keep an **encrypted backup
off-box** so a host suspension is never data loss.

**Back up (do this on a schedule):**
- In the UI: **Settings → Encrypted backup → download**. The file is AES-256-GCM
  encrypted with your backup passphrase. Store it somewhere off the VM.
- The **Readiness** page surfaces backup age so a stale backup is visible.

**Restore (drill this before you need it):**
- **Settings → Restore** and upload the encrypted backup. Restore
  **re-authenticates** (password + TOTP) — it does not trust the current session
  alone — and the app restarts onto the restored database.
- Alternatively, set `BACKUP_PASSPHRASE` and drop a verified backup where the
  server restore-on-boot expects it; verification (`/api/backup/verify`) checks a
  backup decrypts before you rely on it.
- Verify a fresh backup restores into a throwaway instance at least once, so the
  passphrase and the file are known-good.

## Rollback

```bash
git checkout <previous-good-commit>
docker compose -f docker-compose.prod.yml up -d --build
```

Migrations are additive and applied on boot; there is no automatic down-migration,
so a rollback that crosses a schema change should restore the matching database
backup taken before the upgrade.

## Deferred hardening

- **Read-only root filesystem.** Not enabled: the recon CLIs and headless
  Chromium write to `/tmp`, and the entrypoint drops privileges with `gosu`
  (so `no-new-privileges` would break setuid). Enabling it safely needs `tmpfs`
  mounts sized for the scanners and verification against each tool.
- **Plain-node runtime.** The backend runs via `tsx` in production. A compiled
  `dist` run under plain Node is a follow-up (it needs the extensionless /
  bundler-resolution imports handled by an esbuild bundle with native modules
  external).
