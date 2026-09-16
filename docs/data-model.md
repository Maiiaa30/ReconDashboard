# Data model

The backend persists everything to one SQLite file (`DATABASE_PATH`, default
`./data/app.db`), accessed through Drizzle ORM. The source of truth is
`backend/src/db/schema.ts`; this document is a navigable summary. For how the data
is used see [architecture.md](./architecture.md).

## Conventions

- **Timestamps** are integer epoch milliseconds (`mode: 'timestamp_ms'`), so
  Drizzle hands back JS `Date` objects. The default `now` is `unixepoch() * 1000`.
- **Booleans** are integer `0`/`1` (`mode: 'boolean'`).
- **JSON columns** are `text` holding a serialized blob; the comment on each notes
  its shape.
- **Migrations** live in `backend/drizzle/*.sql` and apply on boot
  (`runMigrations()`). They currently run through `0038`. Add one after a schema
  edit with `npx drizzle-kit generate`; if an `ADD COLUMN` needs a non-constant
  default, hand-append the backfill `UPDATE` to the generated `.sql`.
- **Foreign keys** mostly cascade on domain delete. Two deliberate exceptions:
  `jobs.domain_id` has no FK (job history must survive its domain being deleted),
  and denormalized `host` columns on snapshots/reports survive domain edits.

## Auth and session

### `users`
The single operator account. `password_hash` (argon2), `totp_secret` (generated at
seed, 2FA stays disabled until `totp_enabled`), and `last_totp_step` (the highest
accepted TOTP time-step, so a captured code cannot be replayed inside its ~30s
window). `selected_domain_id` and `last_dashboard_viewed_at` persist per-operator
UI state (the active target and the "Today" panel baseline) across browsers.

### `sessions`
Server-side store for @fastify/session: `sid` (primary key), the JSON `session`
blob, and `expires_at`. Pruned periodically.

## Targets and scope

### `domains`
A target (`host`, unique). `mode` is `passive_only` or `active_authorized` - only
the latter permits active/loud scans without an explicit confirm. `profile` and
`owasp_config` are JSON tuning blobs (app characteristics, custom XSS
payloads/paths/params, an optional auth header). `scope_config` is the engagement
scope (`{ allow, deny }` of hosts or CIDRs; empty allow means "anything within the
domain", deny always wins). `authorized_from`/`authorized_until` bound the
authorization window for active scans (null = unbounded).
`monitor_interval_hours` + `last_monitored_at` drive auto-monitoring.

## Audit

### `audit_log`
Append-only ledger of active actions: `actor` (operator or `worker`), `action`
(e.g. `enqueue:nmap_scan`, `job:start`, `job:done`), `domain_id`, `target`, `mode`
at action time, `job_id`, and a short `detail`. Never updated or deleted - it is
legal cover for an authorized engagement. Indexed by `ts` and `domain_id`.

## Recon inventory

### `subdomains`
Discovered hosts under a domain (unique per `(domain_id, host)`). `source`,
`is_new`, and HTTP-probe enrichment (`ip_address`, `http_status`, `title`,
`server`, `scheme`). `waf` marks a host as alive-but-protected behind a WAF/CDN
rather than dead; `waf_brand`/`waf_version`/`waf_source` (migration `0038`) record
the identified WAF vendor from an "Identify WAF" run (`wafw00f` when available, else
the header-based detector - hence `waf_source`; `waf_version` is best-effort and
usually absent for versionless SaaS WAFs). `cert_fp` and `favicon_hash` are
CDN-surviving correlation
signatures (two hosts sharing either are the same asset even on different IPs).
`login_hint` flags a host whose probe saw a login form. Screenshot path/time and
`first_seen`/`last_seen` complete the row.

### `url_corpus`
The full passive URL corpus per domain (Wayback / Common Crawl / urlscan / OTX),
one row per `(domain, url)`. Persisting every URL (rather than the ~50 that used to
survive in a finding blob) feeds JS-recon, parameter discovery, and the OWASP
checks the whole attack surface.

### `assets`
Durable asset inventory, one row per `(domain, kind, value)`. `kind` is `ip` (with
`asn`/`asn_name`/`cdn`), `host` (with resolved `ip`), or `service` (`ip:port`).
Replaces rebuilding the host to IP to port to CVE graph from finding blobs on every
request - now indexable, diffable, and linkable.

### `asset_snapshots`
Per-IP attribute baseline for the change watch (one row per `(domain, ip)`):
`ports`, `tech` (CPEs), up-ness, `title`, `cert_fp`, `status`, `server`,
`redirect`, `content_hash`/`content_length`, `screenshot_hash`. Diffed on each
exposure scan so a new port/tech or a host coming up or going dark raises a
`changed_*` finding. Detect only - never fires a loud scan.

### `asset_cves`
Per-IP CVE ledger powering the "new CVE on a known asset" watch (unique per
`(domain, ip, cve_id)`). `cvss`, `kev`, `first_seen_at`, and `alerted_at` (null =
recorded but not yet alerted, re-driven next run, so a crash between recording and
alerting never loses the alert). The first scan of an asset baselines its CVEs
already-marked, so initial discovery never alerts.

### `asset_findings`
Many-to-many link between an asset and the findings that mention it.

## Jobs and assessments

### `jobs`
The async work queue. `type` (a `JobType`), `status` (`queued` / `running` /
`done` / `error` / `cancelled` / `dead`, where `dead` is a stale or crash-exhausted
job deliberately not auto-resumed), JSON `params`/`result`, `error`, a coarse
`progress` line, denormalized `domain_id` (for dedup and cooldown, no FK),
`attempts` (crash-loop guard), and `cancel_requested` (durable cancel that survives
a restart). Indexed for `claimNextQueued` and per-target pending/cooldown lookups.

### `assessment_runs`
A server-owned, phased assessment workflow: `profile`, `name`, `status`
(`queued` / `running` / `completed` / `partial` / `cancelled`), `confirm_active`,
and `current_phase`/`total_phases`. A run advances through ordered phases so later
testing consumes assets discovered by earlier ones and stays inspectable after a
refresh or restart.

### `assessment_steps`
One logical workflow step of a run (unique per `(run_id, key)`): `label`, `phase`,
`position`, `action` (discover / exposure / ...), `target_strategy` (`domain` /
`live_web` / `live_hosts`), `status`, and a JSON `jobs` array of
`{ id, target }` recording the concrete per-target jobs.

### `assessment_executions`
Durable, normalized evidence for each concrete target attempt (unique per
`job_id`): `target`, `attempt`, `status`, `outcome`, `reason`, a JSON `summary`,
and `findings_produced`/`high_findings` counts. Kept because general job rows are
retention-pruned, so assessment history must not depend on them.

### `assessment_run_findings`
Finding identities observed by a completed run (unique per `(run_id, finding_key)`):
`finding_key`, `type`, `title`, `target`, `score`, `severity`, `status`. Makes
run-to-run new/resolved/regressed comparisons stable even after live findings are
updated by later scans.

## Findings and workflow state

### `findings`
The core evidence table. `type` (a finding type string, e.g. `owasp`, `tool`,
`api`, `secret`, `authz`, `param`, `cve_new`, `asset_change`), JSON `data`,
`score`, JSON `tags`, and the triage `status` (`open` / `confirmed` /
`retest_pending` / `retest_passed` / `false_positive` / `resolved` / `ignored`) +
`note`. Typed correlation columns are derived on write: `severity` (the one
canonical bucket for the score, so report and snapshot agree), `host`/`ip`/`url`
(join keys promoted out of the JSON blob), and `job_id` (the producing scan).
`dedupe_key` gives each logical finding a stable identity so a re-scan upserts the
same row. `created_at` is first-seen (never touched by the upsert); `last_seen_at`
is refreshed on every upsert, so the pair gives discovery age plus freshness.
`retest_requested_at` stamps when the operator marked it for retest. Indexed by
domain, `(score, created_at)` (the keyset sort), dedupe lookup, status, and type.
Rows created by the scan-import path (`POST /api/domains/:id/import`, e.g. Nuclei
JSONL / Nmap XML / generic findings JSON) upsert through the same `addFinding` /
`dedupe_key` machinery the native scanners use and carry an `imported` tag; imported
recon (host lists, httpx JSONL, URL lists) instead lands in `subdomains` /
`url_corpus`, scoped to the domain with out-of-scope entries dropped.

### `finding_links`
Typed relational edges between findings (unique per `(from_id, to_id, kind)`):
`kind` is `confirms` (a PoC proves another finding), `evidence_for`, `same_asset`,
or `chained_from`. Makes relationships queryable instead of inferred by naming
convention.

### `skill_step_state`
Manual overrides for methodology steps (unique per `(domain_id, skill_id,
step_key)`): `state` is `done` (covered even without a proving job/finding) or
`skipped` (excluded from the skill's coverage denominator). Absence of a row means
purely auto-derived status.

### `next_action_state`
Operator disposition for the deterministically generated next actions (unique per
`(domain_id, action_key)`): `state` (`attempted` / `completed` / `dismissed`) plus
a frozen `snapshot` of the recommendation. The recommendation itself is rebuilt
from current evidence; this table only keeps the human workflow state across
restarts.

### `report_snapshots`
Immutable, frozen engagement reports: the full `content_md` + `content_html` as of
a point in time, plus a JSON `meta` count summary. Later re-scans never mutate what
a delivered report says. `host` is denormalized so the snapshot survives domain
edits. Optionally linked to an `assessment_run_id`.

## Operator content

### `notes`
Free-form notes, optionally scoped to a domain (null = global). `title`, `body`.
Can be pushed to Discord.

### `drawings`
Excalidraw canvas scenes: `name` and a JSON `data` blob, optionally domain-scoped.

## HTTP lab (Replay)

### `captured_requests`
Requests captured by the browser extension for a target, awaiting replay/review.
`method`, `url`, `host`, JSON `headers` (order-preserving `[name, value]` pairs),
`body`, and `source`. Passive record only - the operator explicitly re-sends via
the Replay tool. Ingested through the `CAPTURE_TOKEN`-guarded route.

### `identities`
Named request identities (A / B / anonymous) reusable across Repeater, Intruder,
and authz_diff (unique per `(domain_id, name)`), so credentials are defined once.
`headers` is a JSON `{ name: value }` map merged onto the outgoing request;
`is_anon` marks a credential-stripped identity.

### `replay_history`
One row per request sent from the Replay tool, with its response, so past requests
can be revisited and re-sent. Records `identity_id` (which identity sent it), the
request (`method`, `url`, JSON `req_headers`, `req_body`) and the response
(`status`, `status_text`, `time_ms`, `resp_bytes`, JSON `resp_headers`, capped
`resp_body`).

### `payload_sets`
Operator-defined fuzz lists for the Intruder/Repeater (unique `name`): `category`
and a JSON `payloads` string array. Built-in sets ship in code; this table holds
only the user's own lists, so there is no filesystem path-traversal surface.

### `match_replace_rules`
Session-wide request-rewrite rules for the Repeater/Intruder (inject an auth
header, swap a CSRF token, rewrite Host). `domain_id` null = a global rule.
`enabled`, `part` (`url` / `header` / `body`), `match`, `replace`, `is_regex`.
Applied once in `sendRawRequest` before sanitize + redirect handling.

## Exported types

`schema.ts` exports `$inferSelect` row types for the tables other modules consume
directly (`User`, `Domain`, `Subdomain`, `Job`, `AuditEntry`, `PayloadSet`,
`MatchReplaceRuleRow`, `UrlCorpusRow`, `AssetRow`, `FindingLinkRow`, `IdentityRow`,
`CapturedRequest`, `ReplayHistoryRow`, `AssessmentRunRow`, `AssessmentStepRow`).
