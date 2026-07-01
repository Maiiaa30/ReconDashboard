# Recon Dashboard

A single-user, self-hosted red team recon dashboard. One operator, used to track
assets and recon data for **authorized** engagements only. Dark, modern UI.

> Status: **Actively developed.** Auth, domains, subdomain monitoring, exposure,
> OSINT (with tech fingerprint + Wayback/Common Crawl/urlscan/OTX), gated active
> scans + extra tools, an HTTP-based OWASP engine, finding triage, engagement
> reports, per-domain auto-monitoring, notes (with Discord push), Excalidraw
> canvas, rules-based scoring, unit tests, and encrypted backup are implemented.

## Modules

| Module | What it does | Active? |
|---|---|---|
| **Domains** | Add/track targets; per-domain `passive_only` vs `active_authorized` mode; per-domain auto-monitoring (re-run recon every N h); KPI overview | — |
| **Intel** | Rules-based triage view scoped to the selected domain | passive |
| **Subdomains** | Passive discovery via crt.sh + certspotter + subfinder; HTTP-probe enrichment; diff + flag new; Discord alert; exports | passive |
| **Screenshots** | Headless-Chromium gallery + lightbox | passive |
| **Fuzzing** | `ffuf` content discovery with target + wordlist pickers; sortable result columns | ACTIVE |
| **Exposure** | "Shodan of each domain" via Shodan InternetDB + cvedb (free, no key) | passive |
| **OSINT** | DNS, WHOIS, cert-transparency, zone-transfer, InternetDB, **server/tech fingerprint** (OS/server/CDN/stack), and **archived-URL sources** (Wayback, Common Crawl, urlscan.io, OTX) | passive |
| **WAF / Origin** | Origin-IP discovery behind Cloudflare/WAF | passive |
| **WHOIS** | Ad-hoc registration lookup for any domain **or IP** (not domain-scoped) | passive |
| **Check Host** | Ad-hoc reachability: ICMP ping + TCP connect + DNS + HTTP (not domain-scoped) | passive |
| **Scans** | `nmap` / `nuclei` (with template-tag presets) / `ffuf` — **gated behind `active_authorized`, loud** | ACTIVE |
| **Tools** | `katana` (crawl), `naabu` (ports), `dalfox` (XSS), `sslscan` (TLS), WordPress enum — gated | ACTIVE |
| **OWASP** | Direct **HTTP active checks** (headers, exposed `.env`/`.git`, reflected XSS, open redirect, CORS, TRACE, listings) + a complementary nuclei pass. **Target-aware**: auto-tests the real params discovered for the target + per-domain custom payloads/paths and an auth header | ACTIVE |
| **Findings** | Scored, deduped, with a "why this score" explanation + CVE detail; **triage lifecycle** (open/confirmed/false-positive/resolved/ignored) + notes; tag/status filters; CSV/JSON export; **per-domain Markdown report** | — |
| **Notes** | Markdown notes, global or per-domain; one-click **push to Discord** | — |
| **Canvas** | Excalidraw board, auto-saved to the DB | — |
| **Logs** | Live activity log — KPI summary, per-job target, type filter, **cancel queued jobs** | — |
| **Settings** | 2FA enroll, change username/password, system status, encrypted backup | — |

All recon work runs **server-side** as background jobs (a `jobs` table polled by
an in-process worker — no Redis). Active scans/tools never run unless the target
domain is `active_authorized` (or the operator explicitly confirms a one-off run
on a passive domain), every subprocess is invoked with an explicit argument array
(never a shell string), and outbound HTTP checks refuse targets that resolve to
internal/private addresses (SSRF guard).

## Stack

- **Frontend:** React + Vite + TypeScript + Tailwind CSS (single SPA)
- **Backend:** Node.js + Fastify + TypeScript (REST API)
- **DB:** SQLite via Drizzle ORM (`better-sqlite3` driver)
- **Packaging:** Docker + Docker Compose

## Layout

```
.
├── backend/          Fastify API + Drizzle/SQLite
├── frontend/         Vite React SPA
├── docker-compose.yml
├── .env.example
└── README.md
```

## Configuration

Copy the example env file and edit it. **Never commit `.env`.**

```bash
cp .env.example .env
```

Phase 1 also uses:

- `SESSION_SECRET` — session cookie signing secret, **min 32 chars**. Generate one:
  `node -e "console.log(require('crypto').randomBytes(48).toString('hex'))"`
- `ADMIN_USERNAME` / `ADMIN_PASSWORD` — the single operator account, seeded on
  first run. Set a real password before any real use (it warns if left as
  `change-me`). The server refuses to start if `SESSION_SECRET`, `ADMIN_USERNAME`,
  or `ADMIN_PASSWORD` are missing.

Optional:

- `DISCORD_WEBHOOK_URL` — enables new-subdomain alerts and the per-note
  "Send to Discord" button (silent no-op if unset).
- `AI_PROVIDER` — scorer selection; defaults to the deterministic `rules`
  scorer (an Ollama provider is a disabled placeholder).

## First run & login

On first boot the backend applies migrations and creates the operator account
from `ADMIN_USERNAME` / `ADMIN_PASSWORD`. It also generates a TOTP secret and logs
an `otpauth://` URL once — **2FA starts disabled**, so you log in with just
username + password. You can enable 2FA later from **Settings → Two-factor
authentication** in the UI (no re-deploy needed).

Open the frontend, log in with your `.env` credentials, and you land on the
dashboard shell (module nav placeholders; functional modules arrive in later
phases). Any `/api/*` route except `/api/health` and `/api/auth/login` returns
**401** without a valid session.

> The operator is seeded only when there are **no** users yet. To re-seed with
> different credentials locally, stop the backend, delete `backend/data/app.db*`,
> and boot again. In Docker, the DB lives in the `app-data` volume — reset it with
> `docker compose down -v`.

> **Upgrading a running Docker stack from Phase 0:** rebuild the images so the new
> backend (with auth) is used — `docker compose up --build`. Migrations run
> automatically on boot.

## Run option A — Docker Compose (target setup)

Requires Docker Desktop / Docker Engine with the Compose plugin.

```bash
docker compose up --build
```

- Frontend: http://localhost:5173
- Backend health: http://localhost:3001/api/health

The SQLite database lives in the named `app-data` volume, so it survives
`docker compose down` and rebuilds. (It is wiped only by `docker compose down -v`.)

## Run option B — Local (no Docker)

Useful if Docker isn't installed yet. Run the two apps in separate terminals.

**Backend:**

```bash
cd backend
npm install
npm run dev
```

**Frontend:**

```bash
cd frontend
npm install
npm run dev
```

Open http://localhost:5173 — the page should show **Backend health: ok** with a
green dot. The Vite dev server proxies `/api/*` to the backend on port 3001.

The local SQLite file is created at `backend/data/app.db` (gitignored).

## Encrypted backup & restore

From **Settings → Encrypted backup**, download an AES-256-GCM encrypted snapshot
of the database (scrypt-derived key from your passphrase). To restore it back to a
plain SQLite file:

```bash
cd backend
node scripts/restore-backup.mjs path/to/recon-backup-XXXX.rdb restored.db
# (prompts for the passphrase, or set BACKUP_PASSPHRASE)
```

Then put `restored.db` where `DATABASE_PATH` points (or into the Docker `app-data`
volume). Keep the passphrase safe — without it the backup cannot be decrypted.

## Recon CLI tools

The backend Docker image installs `nmap`, `whois`, `subfinder`, `nuclei`, `ffuf`,
`dig`, `iputils-ping`, `sslscan`, `chromium`, and the extra release binaries
`katana`, `naabu`, and `dalfox` (best-effort — a moved release URL never fails
the build). If a tool is missing (e.g. running the backend locally without
Docker), the app degrades gracefully: passive discovery still works, the OWASP
HTTP checks and WordPress enum need no binary, and anything binary-backed reports
the tool as unavailable instead of crashing. **Settings → System status** (and
`GET /api/meta/status`) shows which tools are detected.

The OWASP HTTP engine and the WordPress enumeration are implemented in-process
(no external binary), so the OWASP tab is useful even without nuclei installed.

## Deployment note

Locally you run `docker compose up`. Later this runs on an Oracle Always Free /
Hetzner VM **behind Tailscale**. The app is never exposed to the public internet;
there is no public port mapping in production beyond what Tailscale reaches, and
no public TLS/ACME is configured here by design.

## Security ground rules (apply from day one)

- Security tooling is **server-side only**; every action is triggered from the UI.
- No raw shell input is ever executed.
- No shell command strings are built from user input — subprocesses use
  `execFile`/`spawn` with explicit argument arrays.
- All domain/host inputs are validated against a strict allowlist regex before use.
- No secrets in code — everything sensitive comes from `.env`.
- Active/loud scans and tools are gated behind per-domain `active_authorized`
  (a passive domain requires an explicit per-run confirmation), and every active
  target must belong to the authorized domain.
- Outbound HTTP checks (OWASP engine, tools, fingerprint, check-host) refuse
  targets that resolve to internal/private/loopback IPs (SSRF defense), and the
  security-critical validation is covered by unit tests (`cd backend && npm test`).
- Only use this against assets you are explicitly authorized to test.
