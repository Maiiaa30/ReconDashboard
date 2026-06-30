# Recon Dashboard

A single-user, self-hosted red team recon dashboard. One operator, used to track
assets and recon data for **authorized** engagements only.

> Status: **Complete (Phases 0–8).** Auth, domains, subdomain monitor, exposure,
> OSINT, gated active scans, notes, Excalidraw canvas, rules-based scoring, and
> encrypted backup are all implemented.

## Modules

| Module | What it does | Active? |
|---|---|---|
| **Domains** | Add/track targets; per-domain `passive_only` vs `active_authorized` mode | — |
| **Subdomains** | Passive discovery via crt.sh + subfinder; diff + flag new; Discord alert | passive |
| **Exposure** | "Shodan of each domain" via Shodan InternetDB + cvedb (free, no key) | passive |
| **OSINT** | Aggregated DNS, WHOIS, crt.sh, InternetDB for a target | passive |
| **Scans** | `nmap` / `nuclei` / `ffuf` as background jobs — **gated behind `active_authorized`, default-off, loud** | ACTIVE |
| **Findings** | Everything scored by the rules-based scorer, highest priority first | — |
| **Notes** | Markdown notes, global or per-domain | — |
| **Canvas** | Excalidraw board saved to the DB | — |
| **Jobs** | Live status of all background jobs | — |
| **Settings** | 2FA enroll, system status, encrypted backup download | — |

All recon work runs **server-side** as background jobs (a `jobs` table polled by
an in-process worker — no Redis). Active scans never run unless the target domain
is explicitly marked `active_authorized`, and every subprocess is invoked with an
explicit argument array (never a shell string).

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

The backend Docker image installs `nmap`, `whois`, `subfinder`, `nuclei`, and
`ffuf`. If a tool is missing (e.g. running the backend locally without Docker),
the app degrades gracefully: passive discovery still works via crt.sh, and active
scans report the tool as unavailable instead of crashing. **Settings → System
status** shows which tools are detected.

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
- Active/loud scans are gated behind per-domain `active_authorized`, and active
  scan targets must belong to the authorized domain.
- Only use this against assets you are explicitly authorized to test.
