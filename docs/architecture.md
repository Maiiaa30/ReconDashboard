# Architecture

This document describes how the Recon Dashboard is put together: its deployment
posture, the request lifecycle, the backend and frontend structure, and the job
model. For the persisted schema see [data-model.md](./data-model.md); for the
production runbook see [production.md](./production.md).

## What it is

A single-operator, self-hosted red-team recon dashboard for authorized
engagements. One operator drives passive reconnaissance and, against targets they
have explicitly authorized, active/loud scanning, then triages the resulting
findings into an engagement report. It is not a multi-tenant SaaS: there is one
account, no RBAC, and the intended network exposure is a private Tailscale
tailnet, never the public internet.

The whole system is a Fastify backend plus a React single-page app, backed by one
SQLite file and an in-process job worker. There is no external queue, cache, or
database server.

## Deployment topology

Two stacks share the same code:

- **Development** (`docker-compose.yml`): Vite dev server on `:5173` and the
  Fastify backend on `:3001` as separate origins. Vite proxies `/api` to the
  backend. Source is bind-mounted for fast iteration.
- **Production** (`docker-compose.prod.yml`): a single origin. The frontend is
  built to static assets and served by the backend from one tailnet port;
  `NODE_ENV=production`, no read-write source mounts, and a container healthcheck
  on `/api/health`. The backend is compiled to a plain-Node ESM bundle
  (`dist/server.mjs` via esbuild, so `tsx` is not a runtime dependency).

Single-origin serving is what makes the CSRF Origin check meaningful: in the
multi-port dev proxy an `Origin == Host` comparison would false-reject, so the
Origin guard is a no-op unless `TRUSTED_ORIGINS` is set (production only).

## Stack

- **Frontend**: React 18 + Vite + TypeScript + Tailwind v3, a single SPA. Heavy
  libraries (Excalidraw canvas, graph/diagram code) are lazy-loaded so they never
  block the first useful screen. A CI bundle budget guards first-load JS.
- **Backend**: Node 22 + Fastify 5 + TypeScript, Drizzle ORM over better-sqlite3,
  an in-process job worker (no Redis). Auth is argon2 (@node-rs/argon2) +
  @fastify/session (SQLite store) + optional TOTP (otplib) + @fastify/rate-limit.
- **Recon tooling** baked into the backend image: subfinder, nuclei, ffuf, nmap,
  whois, dig, sslscan, sqlmap, chromium, and best-effort katana, naabu, dalfox.
- **Tests**: vitest on both sides; Testing Library + jsdom + axe-core on the
  frontend.

## Request lifecycle

`backend/src/index.ts` exposes `buildApp()`, which assembles the app without
listening or starting background workers, so an integration test can import it and
drive it with `app.inject()`. `main()` adds the background workers and calls
`listen()`. Startup order inside `buildApp()`:

1. **Error + not-found handlers.** A consistent error envelope: schema-validation
   failures become a clean `400`, `5xx` hides internals in production. The
   not-found handler implements the SPA fallback - an unmatched non-API `GET`
   returns `index.html` so the client router can resolve the route; API misses and
   non-GET misses still return a JSON `404`.
2. **Migrations + seed.** `runMigrations()` applies the Drizzle SQL migrations on
   boot; `seedAdmin()` creates the operator account on first run. The scorer is
   instantiated eagerly so a misconfigured `AI_PROVIDER` fails fast. A one-time
   `dedupeExistingFindings()` cleans up pre-dedup duplicates.
3. **Plugins.** Rate-limit (registered globally disabled, opted into per-route -
   login), cookie, and session (signed httpOnly cookie, `sameSite=strict`,
   `secure` in production, SQLite-backed store).
4. **Hooks, in order:**
   - `originGuard` - CSRF Origin check on state-changing session routes; no-op
     unless `TRUSTED_ORIGINS` is set. Runs first so a forged cross-origin mutation
     is refused regardless of session state. The capture ingest route is exempt.
   - `authGuard` - default-deny; runs after the session plugin has loaded the
     session.
   - `registerResponseValidation` - a preSerialization hook that validates a
     flagged route's 2xx payload against its transport contract (see Contracts
     below).
5. **Routes.** `GET /api/health` and the auth routes are public; every feature
   route is registered behind the auth guard.
6. **Static SPA.** When `STATIC_DIR` points at the built SPA (production),
   @fastify/static serves it at `/`; in dev this is unset and Vite serves the
   frontend.

## Backend structure

`backend/src/` is organized by responsibility rather than by feature page:

- **`routes/`** - Fastify route modules, one per capability area (domains,
  findings, recon, scans, tools, owasp, replay, capture, assessments, audit, meta,
  and so on). Routes validate input, enforce gating, enqueue jobs, and read from
  the stores. They hold no scanning logic themselves.
- **`sources/`** - passive and active data collectors: crtsh, certspotter,
  subfinder, internetdb, cvedb, dns, whois, httpProbe, takeover, screenshot,
  fingerprint, the passive URL sources (wayback / commoncrawl / urlscan / otx),
  ASN/TLS-cert harvesters, cloud-bucket enum, JS recon, and the binary-tool
  runners (`binTools.ts`: katana/naabu/dalfox/sslscan/sqlmap plus the HTTP
  routines wp-enum/bypass403/methods/datastores). Every collector reaches a target
  through the guarded transport (see Safety below), never a raw `fetch`.
- **`owasp/`** - the HTTP active-checks engine (`activeChecks.ts`) plus per-class
  modules (CSP/HSTS, CORS, VCS/backups, JWT crack + alg-confusion, open-redirect /
  SSRF-candidate, SSTI, blind injection confirmation, deserialization markers).
  `catalog.ts` maps categories to nuclei tags and reference payloads.
- **`scoring/`** - deterministic, rules-based scoring (`rules`, `taxonomy`,
  `types`). Every score function emits `reasons`, stored on the finding, so the UI
  can explain a score. Scoring never calls an LLM.
- **`findings/`** - `store.ts` (`addFinding` upserts by `findingKey`; `listFindings`
  and the paged `queryFindings`/`summarizeFindings`), `severity.ts` (the one
  canonical severity bucket shared by report and snapshot), `report.ts` (Markdown +
  self-contained HTML report), the retest lifecycle, CVE watch, and finding links.
- **`assessments/`** - the server-owned, phased assessment workflow that advances
  a run through ordered phases so later testing consumes assets discovered by
  earlier phases (see `assessments/runs.ts`, the orchestrator).
- **`skills/`** - packaged recon methodologies: `registry.ts` (skill/step
  definitions + `appliesWhen` + runnable action), `methodology.ts`
  (`buildMethodology` - coverage derived from stored jobs + findings),
  `overrides.ts` (manual done/skip).
- **`jobs/`** - the queue, worker, scheduler, chains, and per-type handlers (see
  below).
- **`db/`** - `schema.ts` (Drizzle table definitions), `migrate.ts`, connection
  setup. **`domains/`** - correlation, chain suggestion, scan policy, the AI
  advisor. **`auth/`, `backup/`, `notify/`, `corpus/`, `identities/`, `replay/`,
  `assets/`, `subdomains/`, `capture/`, `audit/`, `ai/`** hold their respective
  stores and helpers. **`util/`** - `exec.ts` (execFile wrappers), `validate.ts`
  (input + SSRF validation), `scope.ts`, `csv.ts`, `http.ts`, `llm.ts`.

## Job model

Recon runs as asynchronous jobs, not inline in the request. A route enqueues a
job; the in-process worker claims and runs it.

- **Queue** (`jobs/queue.ts`): a `JobType` union of every job kind. `claimNextQueued`
  pulls the oldest queued job on each worker poll. `cancelJob` flips a queued job
  to `cancelled` and requests cancel on a running one. A durable `cancelRequested`
  flag survives restarts.
- **Worker** (`jobs/worker.ts`): a per-job 20-minute timeout. `JobContext` gives a
  handler `progress(msg)` (a coarse human progress line) and `signal` (an
  `AbortSignal` threaded into `execFile` so a timeout or an operator cancel kills
  the child process). A crash-loop guard dead-letters a job after too many claims
  rather than re-queuing it forever.
- **Scheduler** (`jobs/scheduler.ts`): a 60-second tick that enqueues passive
  discovery + exposure per domain when its monitor interval has elapsed, with a
  pending-job dedup and per-domain isolation.
- **Chains** (`jobs/chains.ts`): a post-completion hook that chains passive follow-on
  work (discovery to exposure + screenshots, exposure to osint + api_discovery).
  Chains are passive-only by construction.

### Safety and gating

The active/loud capability is the sensitive surface, so it is gated at several
layers that any new job must satisfy:

- **`LOUD_TYPES`** in `jobs/queue.ts` marks the active job kinds
  (nmap/nuclei/ffuf/owasp_active/tool_scan/origin_scan/intruder/cve_verify/
  authz_diff/param_discovery/inject_confirm/jwt_confuse). Loud jobs are never
  auto-resumed after a crash - an interrupted active scan re-firing on the next
  boot is an authorization and noise hazard - and are never referenced by the
  scheduler or the chain hook.
- **`assertScanAllowed`** (`domains/scanPolicy.ts`): an active job is enqueued only
  from a route that passes the gate - correct domain mode (`active_authorized`, or
  `passive_only` with an explicit `confirm`), engagement scope (allow/deny hosts
  and CIDRs, deny wins), authorization window, per-target cooldown, and a pending
  guard - and an audit row is written before the `202`.
- **Guarded transport**: every request to a target goes through
  `sendRawRequest` / `guardedFetch` / `guardedFetchRaw`, which re-resolve all
  A/AAAA records and redirects and refuse internal/private/loopback/CGNAT/ULA
  addresses (SSRF block). A lint rule forbids a raw `fetch(` in `sources/**` and
  `owasp/**`.

The definition of done for a new loud job is therefore: add the `JobType` and put
it in `LOUD_TYPES`, register the handler, gate the route, write the audit row, add
a `FindingType`/`findingKey` if new, and unit-test the pure core.

## Frontend structure

`frontend/src/` is a single SPA:

- **`App.tsx`** owns auth state (loading / authed / anon), the session-expiry
  banner, and the connection subscriber that routes a mid-session 401 back to
  login. It wraps the app in the toast, confirm, and app-state providers.
- **`components/`** - the shell and chrome: `Shell.tsx` (layout + target selector
  + navigation), `PageContent.tsx` (the lazy workspace registry - every page is a
  dynamic import), `navigation.ts` (the collapsible specialist-group model),
  `appRoute.ts` (URL routing without a framework - bookmarkable global and
  `/engagements/:id/:page` routes with Back/Forward), plus the reusable primitives
  (`Tabs`, `Confirm`, `Toast`, `ConnectionBanner`).
- **`pages/`** - one workspace per capability. The three largest were split by
  capability into subfolders (`findings/`, `replay/`, `apisurface/`) so no page is
  an unmanageable monolith.
- **`api/`** - the transport seam. `http.ts` owns fetch, cancellation
  (`AbortSignal`), JSON handling, and `ApiError`. Per-domain client modules
  (`auth`, `home`, `domains`, `recon`, `scans`, `intel`, `replay`, `captures`,
  `jobs`, `findings`, `tools`, `content`, `system`) each own their request methods
  and interfaces; `api.ts` is a thin facade that composes them by spread and
  re-exports every type, so call sites import `{ api, type Finding }` from one
  place. `api.facade.test.ts` pins the public method set.
- **`state.tsx`** - the app-wide provider (`useApp`), host derivation, and
  `usePoll` (the lifecycle-aware, AbortSignal-cancelling polling hook that most
  live pages use).

### Contracts

Response shapes are validated at runtime against zod schemas on both sides of the
wire:

- **Frontend** (`api/schemas.ts`): core transport objects are zod schemas; their
  TypeScript types are inferred from those schemas (single source). `http.ts`
  validates a response against an opt-in `schema` argument and raises a
  `ContractError` on mismatch.
- **Backend** (`types/contracts.ts` + `types/responseValidation.ts`): a mirrored
  set of zod schemas and a preSerialization hook that validates a flagged route's
  2xx payload. In dev/test a mismatch throws (loud, fails CI); in production it is
  logged and served anyway so a contract quirk never takes a live response down.

The two schema sets are mirrored by hand today; a single shared package (so both
import one definition) is the remaining monorepo step.

## Persistence

One SQLite file (`DATABASE_PATH`, default `./data/app.db`), accessed through
Drizzle ORM over better-sqlite3. Timestamps are stored as integer epoch
milliseconds; booleans as integer 0/1. Migrations live in `backend/drizzle/` and
apply on boot. High-volume tables (findings, audit, subdomains, captures) support
server-side filtering, keyset cursor pagination, and summary endpoints. The full
table reference is in [data-model.md](./data-model.md).

Backups are AES-256-GCM encrypted; `backup.ts` verifies and can stage a
restore-on-boot swap. The audit log is append-only and intentionally never pruned
(it is legal cover for an authorized engagement); terminal job rows and old
captures are pruned on a retention interval.

## Configuration

Configuration is environment-driven (`backend/src/config.ts`, documented in
`.env.example`). Notable keys: `SESSION_SECRET` (required), `DATABASE_PATH`,
`PORT`/`HOST`, `ADMIN_USERNAME`/`ADMIN_PASSWORD`, `CAPTURE_TOKEN` (browser-capture
ingest), `STATIC_DIR` (enables single-origin serving), `TRUSTED_ORIGINS` (enables
the Origin guard), the `LLM_*` trio (narrative-only, default off and fail-soft),
`LEAK_PROVIDER`/`LEAK_API_KEY`, `DISCORD_WEBHOOK_URL`, `BACKUP_PASSPHRASE`, and the
retention/schedule tunables. The LLM is used only for narrative summaries and the
AI advisor; it never touches scoring, which stays deterministic.

## Testing and CI

Backend: `npm run typecheck`, `npm run lint`, `npm test` (vitest), and the esbuild
`npm run build`. Frontend: `npm run lint`, `npm test` (vitest + Testing Library +
jsdom + axe), `npm run build`, and the bundle-budget check. GitHub Actions on
Node 22 is the final clean-environment gate. jsdom has no layout or canvas engine,
so axe contrast checks are disabled in unit tests and contrast still needs a
real-browser pass.
