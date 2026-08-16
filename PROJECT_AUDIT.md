# Recon Dashboard Project Audit

Date: 2026-08-16

Baseline reviewed: `3434b12` on `main`

Scope: architecture, clean code, correctness, UX, testing, dependencies, deployment, and product direction

## Executive verdict

Recon Dashboard has a stronger technical core than its interface currently communicates. The backend has clear authorization boundaries, deterministic scoring, durable assessment evidence, SSRF-aware network access, reproducible migrations, and a meaningful automated test suite. It is not a prototype held together by mock data.

The main risk is now imbalance: capability has grown faster than the product and maintenance foundations around it. The app has 35 page modules, 34 permanent sidebar entries, 29 polling consumers, and several very large files. The backend has 439 passing tests, while the frontend has no automated tests or lint command. Production deployment also still uses the development servers and exposes the frontend and backend separately.

The best next move is not another large scanner batch. Stabilize the frontend, production topology, navigation, data contracts, and high-volume query behavior first. After that, add only features that improve evidence quality, authenticated coverage, or retesting.

## Validation baseline

The following checks passed before the audit changes:

- Backend TypeScript typecheck
- Backend ESLint
- Backend test suite: 59 files, 439 tests
- Frontend TypeScript and Vite production build
- Production dependency audit: zero known vulnerabilities in both applications
- GitHub Actions covers backend lint/typecheck/tests and frontend typecheck/build

The full backend dependency audit reports four moderate development-only findings through the `drizzle-kit` dependency tree and an old nested `esbuild`. The suggested automatic fix is a major downgrade, so it should not be applied blindly. Production dependencies are unaffected.

## Fixes applied during this audit

### 1. Polling is serialized and lifecycle-aware

The shared polling hook previously had no way to coordinate asynchronous work. Overlapping responses can arrive out of order, waste work, and replace newer state with older data. The hook now supports lifecycle signals and serializes async callbacks that return their work; the core workflow loaders were migrated to that contract. Together they now:

- allows only one request per poller at a time;
- aborts the lifecycle signal when the page, target, or poller changes;
- prevents unhandled promise rejections from interval callbacks;
- keeps unexpected polling failures observable in the browser console.

### 2. Core workflow pages no longer show another target's data

Command Center, Next Actions, Assessment Runs, Reports, Change History, and Scan Profiles now clear target-scoped state when the selected engagement changes. Their asynchronous loaders ignore results from an obsolete page lifecycle.

### 3. Important load failures are visible

The same core workflow pages no longer convert a failed request into a misleading empty state. They show an explicit load failure and explain that automatic polling will retry.

### 4. Finding data uses stronger backend types

Several unnecessary `any` casts were removed from report export, CVE verification, methodology coverage, OWASP URL collection, and sitemap assembly. The common finding-data type now describes shared endpoint, server, item, and legacy URL-sample fields.

## What is already good

### Safety and authorization

- Active work is centrally gated by target mode, engagement scope, authorization windows, and cooldowns.
- Loud job types are explicitly classified and are not silently resumed after crashes.
- Target HTTP helpers re-resolve redirects and guard against internal-address access.
- Subprocess execution uses argument arrays instead of shell interpolation.
- Session cookies are HTTP-only and SameSite strict.
- Active actions are recorded in an append-only audit trail.

### Evidence and workflow integrity

- Assessment runs persist exact target attempts, degraded/unavailable outcomes, retries, comparisons, and report links.
- Finding scoring is deterministic and records human-readable reasons.
- Re-scans preserve triage state and distinguish first seen from last seen.
- Reports can be frozen as immutable snapshots.
- The new responsibility split between Command Center, Next Actions, Scan Profiles, Assessment Runs, and Methodology is much clearer.

### Backend engineering

- The application can be constructed independently from its listener and background workers, enabling integration tests.
- Database migrations are explicit and applied at startup.
- Core scheduling, worker orchestration, scoring, recon parsing, assessment execution, and security boundaries have automated coverage.
- CI uses reproducible `npm ci` installs and cancels superseded runs.

## Prioritized problems

### P0 - Address before calling the deployment production-ready

#### Production still runs development servers

Both Docker images start their development commands. The frontend runs Vite on port 5173, the backend runs through `tsx`, source directories are mounted, `NODE_ENV` is set to development, and both ports are published. This is convenient locally but is not a production topology.

Recommended change:

1. Build the frontend in a multi-stage image.
2. Serve static assets and the API from one origin, either through the backend or a small reverse proxy.
3. Compile the backend and run plain Node in production.
4. Set `NODE_ENV=production`, use read-only containers where practical, and expose only one tailnet-facing port.
5. Add an Origin check for state-changing session-authenticated routes once same-origin serving exists.
6. Add container health checks and a documented backup/restore drill.

#### Frontend has no automated quality gate beyond compilation

There are no frontend test files, no frontend lint script, and no accessibility test layer. TypeScript catches structural mistakes but not target-switch races, broken interactions, keyboard regressions, filter behavior, or incorrect empty/error states.

Recommended change:

- Add ESLint with React Hooks rules.
- Add Vitest and React Testing Library.
- Start with App/Shell navigation, target switching, Next Actions state transitions, run controls, report creation, and Replay request construction.
- Add axe checks to the highest-value pages.
- Add these commands to CI and require them before merge.

#### Request errors are still often hidden

There are about 45 empty `.catch(() => {})` handlers in the frontend. Some are valid best-effort background operations, but many load primary page data. A failed API call can therefore look identical to “no results.” The audit fixed the central assessment workflow, not every legacy module.

Recommended change:

- Introduce a shared async resource pattern with `loading`, `refreshing`, `error`, and `lastSuccessfulAt`.
- Classify requests as primary, optional, or background; only optional/background failures may be silent.
- Add a global offline/session-expired banner and a consistent retry action.
- Thread `AbortSignal` into the API client so obsolete HTTP requests are cancelled, not only ignored on completion.

### P1 - Highest maintainability and UX return

#### The interface exposes the implementation structure

Thirty-four permanent sidebar entries ask operators to choose a scanner or data source before choosing an outcome. Group labels help, but the product still feels like a tool collection.

Recommended change:

- Keep the primary workflow visible: Portfolio, Command Center, Next Actions, Scope, Assets, Runs, Findings, and Reports.
- Make Intelligence, Testing, HTTP Lab, and System expandable workspaces.
- Remember expanded sections, favorites, and recent modules.
- Keep Ctrl-K for direct expert access.
- Surface specialist modules contextually from assets, findings, and next actions.

#### Navigation is not URL-addressable

The active page is stored in local storage rather than the URL. Browser back/forward, bookmarks, shareable links, opening a finding in a new tab, and restoring a precise run or asset are therefore weak or unavailable.

Recommended change:

- Add lightweight URL routing with routes such as `/engagements/:id/runs/:runId` and `/findings/:findingId`.
- Keep selected engagement, filters, tabs, and focused records in route state where useful.
- Preserve compatibility with the current navigation handoff helpers during migration.

#### Large modules have too many reasons to change

Current hotspots include:

| File | Approximate lines | Main concern |
| --- | ---: | --- |
| `frontend/src/pages/Replay.tsx` | 2,038 | Repeater, Intruder, Authz, identities, payloads, transforms, and rules share one module |
| `frontend/src/pages/Findings.tsx` | 1,169 | Querying, filtering, bulk triage, evidence, links, verification, and export UI are coupled |
| `frontend/src/api.ts` | 1,053 | Every transport type and endpoint lives in one client module |
| `frontend/src/pages/ApiSurface.tsx` | 940 | OpenAPI, GraphQL, JavaScript, JWT, and replay handoffs are coupled |
| `backend/src/db/schema.ts` | 610 | All persistence concepts share one schema module |
| `backend/src/sources/apiSurface.ts` | 607 | Fetching, parsing, normalization, and analysis share one source |
| `backend/src/assessments/runs.ts` | 561 | Persistence, orchestration, evidence, comparison, and snapshots are mixed |

Recommended change:

- Split by domain capability, not arbitrary line count.
- Keep page containers responsible for orchestration and move panels, forms, and pure transformations into focused modules.
- Split the API client into domain clients while retaining one request primitive.
- Separate assessment repository, orchestration, evidence, and comparison logic.
- Add characterization tests before splitting Replay or Findings.

#### Polling and large fixed limits will not scale smoothly

Many views poll every 2.5 to 10 seconds and fetch hundreds or thousands of complete records. Findings, changes, methodology, jobs, and reports repeatedly derive summaries on the client or rescan retained rows on the server. The current SQLite/cached design is reasonable for one operator, but high-volume engagements will make the UI and API increasingly expensive.

Recommended change:

- Add cursor pagination and server-side filtering for findings, jobs, audit, captures, subdomains, and changes.
- Return summary endpoints for KPI cards instead of downloading full collections.
- Replace frequent whole-page polling with event invalidation or a single server-sent-events channel for jobs/runs.
- Use visibility-aware polling and pause nonessential refreshes in background tabs.
- Establish retention/archive policy for the append-only audit ledger.

#### Frontend and backend contracts are compile-time assertions only

The frontend request wrapper casts JSON directly to the requested generic type. Backend finding data is flexible by design, and the frontend still uses broad `any` data in important modules. A backend shape change can compile successfully and fail only at runtime.

Recommended change:

- Define shared transport schemas for core objects and validate at API boundaries.
- Generate or share TypeScript types from those schemas.
- Keep scanner-specific raw payloads under a clearly named `raw` field and normalize fields used by UI/reporting.
- Continue replacing `any` at ingestion boundaries with narrow type guards.

#### Bundle size and eager page loading are unnecessarily high

The production build transforms more than 4,200 modules and emits multiple chunks above 500 kB, including chunks around 1.1 MB and 1.8 MB. Heavy graph, diagram, Canvas, and report dependencies should not affect the first useful screen.

Recommended change:

- Lazy-load every page from Shell.
- Isolate Excalidraw, Mermaid, graph rendering, and PDF-related UI behind dynamic imports.
- Define stable manual chunks only after route-level splitting.
- Record a bundle budget in CI.

### P2 - Important polish and operational maturity

#### Accessibility is inconsistent

The component library has useful semantics, but the application lacks an automated accessibility gate. Icon-only controls, dense tables, custom tabs, graph controls, focus restoration, and status-only color indicators need a deliberate pass.

Recommended change:

- Verify names for every icon-only control.
- Add keyboard and focus behavior to tabs, dialogs, drawers, and graph interactions.
- Add visible focus styles and non-color status text.
- Test Command Center, Findings, Replay, and mobile navigation with keyboard-only use.

#### Operational health is distributed

Tool availability, provider credentials, wordlists, scanner versions, last provider success, queue health, database size, and backup freshness are visible in different places or only in logs.

Recommended change:

- Build one Readiness page/API covering scanner binaries and versions, optional providers, database/migration status, disk space, worker heartbeat, queue age, browser capture heartbeat, backup age, and notification delivery.
- Run a preflight before starting a profile and identify which steps will be unavailable before queueing it.

#### Documentation is feature-rich but not decision-oriented

The README accurately lists capabilities, but it is long and mixes user workflow, product catalog, internals, and deployment. There is no tracked architecture decision record, contribution guide, production runbook, or security policy.

Recommended change:

- Keep README focused on value, quick start, safety, and the normal workflow.
- Add `docs/architecture.md`, `docs/production.md`, `docs/testing.md`, and `docs/data-model.md`.
- Add short architecture decision records for single-origin deployment, job durability, finding identity, and event delivery.
- Add `SECURITY.md` defining authorized use and private disclosure expectations.

## Functionality worth adding after the foundation work

### 1. Asset-centric investigation workspace

Create a durable asset detail route that joins host/IP/service history, technologies, screenshots, requests, findings, runs, changes, and notes. This reduces jumping between source-oriented pages and makes the stored graph useful to an operator.

### 2. Authenticated coverage sessions

Named identities exist, but authenticated coverage is still assembled tool by tool. Add an engagement session that binds an identity, cookie refresh strategy, seed URLs, and authenticated crawl scope. Feed the resulting corpus into API discovery, parameter discovery, OWASP checks, Replay, and retesting.

### 3. Retest and remediation workflow

Turn confirmed findings into explicit retest tasks with owner-free single-operator states: ready, blocked, retest running, passed, and regressed. Preserve before/after evidence and create a client-ready remediation delta report.

### 4. Evidence provenance and freshness

Every normalized result should answer: which tool/provider produced it, against which concrete target, with which version/configuration, at what time, and whether the evidence is stale. Show freshness badges at asset and finding level.

### 5. Import/export interoperability

Support importing common scanner outputs such as Nuclei JSONL, Nmap XML, Burp-compatible requests, and generic findings JSON. Export a stable machine-readable engagement bundle so the dashboard is not a data silo.

### Features to defer

Do not prioritize more standalone scanners, multi-user RBAC, cloud-scale infrastructure, or autonomous exploitation yet. They add surface area without addressing the current product bottlenecks. Multi-user support would also require a deliberate authorization and audit redesign rather than a simple users table expansion.

## Recommended execution order

### Phase 1 - Confidence and production foundation

1. Add frontend lint, tests, and accessibility checks.
2. Convert deployment to compiled, same-origin production serving.
3. Finish consistent request cancellation and visible error states.
4. Add health/readiness checks and backup restore documentation.

### Phase 2 - Product structure

1. Introduce URL routing and deep links.
2. Implement progressive navigation.
3. Split Replay, Findings, API Surface, API client, and assessment orchestration behind characterization tests.
4. Establish shared runtime-validated API contracts.

### Phase 3 - Scale and operator speed

1. Add pagination and summary endpoints.
2. Replace scattered polling with one event stream and cache invalidation.
3. Add the asset-centric investigation workspace.
4. Add freshness/provenance and consolidated readiness.

### Phase 4 - High-value capability

1. Authenticated coverage sessions.
2. Formal retest/remediation workflow.
3. Import/export interoperability.
4. Only then evaluate additional scanners or collaboration features.

## Final recommendation

The project does not need a rewrite. Its backend safety model, persistence, assessment evidence, and test suite are worth preserving. The best path is a controlled product-hardening program: make failures visible, make navigation addressable, make the frontend testable, serve one production application, and decompose only the hotspots protected by tests.

If only one initiative is started next, choose the frontend confidence layer plus same-origin production deployment. That combination removes the largest correctness and operational risks while making every later UX or capability change safer.
