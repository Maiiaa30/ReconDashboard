// Drizzle ORM schema (SQLite).
//
// Timestamps are stored as integer epoch milliseconds (mode: 'timestamp_ms'),
// so Drizzle hands back JS Date objects. Booleans are integer 0/1.

import { sql } from 'drizzle-orm'
import { index, integer, real, sqliteTable, text, unique } from 'drizzle-orm/sqlite-core'

const now = sql`(unixepoch() * 1000)`

// --- Auth --------------------------------------------------------------------

export const users = sqliteTable('users', {
  id: integer('id').primaryKey({ autoIncrement: true }),
  username: text('username').notNull().unique(),
  passwordHash: text('password_hash').notNull(),
  // TOTP secret is generated at seed time; 2FA stays disabled until enabled.
  totpSecret: text('totp_secret').notNull(),
  totpEnabled: integer('totp_enabled', { mode: 'boolean' }).notNull().default(false),
  // Highest TOTP time-step already accepted. A token is rejected if its step is
  // <= this, so a captured code can't be replayed within its ~30s window
  // (otplib.verify alone has no used-token memory — audit §3 #4).
  lastTotpStep: integer('last_totp_step'),
  // Persisted per-operator UI state so the selected target follows the account
  // across browsers/devices (not just this browser's localStorage).
  selectedDomainId: integer('selected_domain_id'),
  // When the operator last opened Home. The "Today" panel diffs new/risky items
  // against this (fallback: last 7 days when null).
  lastDashboardViewedAt: integer('last_dashboard_viewed_at', { mode: 'timestamp_ms' }),
  createdAt: integer('created_at', { mode: 'timestamp_ms' }).notNull().default(now),
  updatedAt: integer('updated_at', { mode: 'timestamp_ms' }).notNull().default(now),
})

// Server-side session store for @fastify/session.
export const sessions = sqliteTable('sessions', {
  sid: text('sid').primaryKey(),
  session: text('session').notNull(), // JSON blob
  expiresAt: integer('expires_at', { mode: 'timestamp_ms' }).notNull(),
})

// --- Targets -----------------------------------------------------------------

export const domains = sqliteTable('domains', {
  id: integer('id').primaryKey({ autoIncrement: true }),
  host: text('host').notNull().unique(),
  label: text('label'),
  // 'passive_only' | 'active_authorized' — active/loud scans require the latter.
  mode: text('mode').notNull().default('passive_only'),
  // App characteristics profile (JSON) used to filter which OWASP tests apply.
  profile: text('profile'),
  // Per-domain OWASP tuning (JSON): custom XSS payloads, extra params/paths,
  // and an optional auth header for authenticated active checks.
  owaspConfig: text('owasp_config'),
  // Auto-monitoring: re-run passive recon every N hours (0 = off).
  monitorIntervalHours: integer('monitor_interval_hours').notNull().default(0),
  lastMonitoredAt: integer('last_monitored_at', { mode: 'timestamp_ms' }),
  // Engagement scope (JSON): { allow: string[], deny: string[] } of hosts or
  // CIDRs. Empty/absent allow = "anything within the domain"; deny always wins.
  // Enforced on active scans so we can't be pointed at out-of-scope assets.
  scopeConfig: text('scope_config'),
  // Authorization window for ACTIVE/loud scans. Outside [from, until] active
  // scans are refused (a real engagement is time-boxed). Null = unbounded.
  authorizedFrom: integer('authorized_from', { mode: 'timestamp_ms' }),
  authorizedUntil: integer('authorized_until', { mode: 'timestamp_ms' }),
  createdAt: integer('created_at', { mode: 'timestamp_ms' }).notNull().default(now),
  updatedAt: integer('updated_at', { mode: 'timestamp_ms' }).notNull().default(now),
})

// --- Audit --------------------------------------------------------------------

// Append-only ledger of active actions against targets. Written at every active
// enqueue and at job start/finish. Never UPDATEd or DELETEd — legal cover for an
// authorized engagement ("who ran what, against whom, when, under which mode").
export const auditLog = sqliteTable(
  'audit_log',
  {
    id: integer('id').primaryKey({ autoIncrement: true }),
    ts: integer('ts', { mode: 'timestamp_ms' }).notNull().default(now),
    actor: text('actor').notNull(), // operator username, or 'worker'
    action: text('action').notNull(), // e.g. 'enqueue:nmap_scan', 'job:start', 'job:done'
    domainId: integer('domain_id'),
    target: text('target'),
    mode: text('mode'), // domain mode at action time
    jobId: integer('job_id'),
    detail: text('detail'), // short JSON/text context (params summary, outcome)
  },
  (t) => [index('audit_ts_idx').on(t.ts), index('audit_domain_idx').on(t.domainId)],
)

export const subdomains = sqliteTable(
  'subdomains',
  {
    id: integer('id').primaryKey({ autoIncrement: true }),
    domainId: integer('domain_id')
      .notNull()
      .references(() => domains.id, { onDelete: 'cascade' }),
    host: text('host').notNull(),
    source: text('source'),
    isNew: integer('is_new', { mode: 'boolean' }).notNull().default(true),
    // Lightweight HTTP probe enrichment (status / title / server / ip).
    ipAddress: text('ip_address'),
    httpStatus: integer('http_status'),
    title: text('title'),
    server: text('server'),
    scheme: text('scheme'),
    // The HTTP probe saw a login form / auth wording — a high-value new host to
    // surface first in the "Today" panel.
    loginHint: integer('login_hint', { mode: 'boolean' }).notNull().default(false),
    probedAt: integer('probed_at', { mode: 'timestamp_ms' }),
    screenshotPath: text('screenshot_path'),
    screenshotAt: integer('screenshot_at', { mode: 'timestamp_ms' }),
    firstSeen: integer('first_seen', { mode: 'timestamp_ms' }).notNull().default(now),
    lastSeen: integer('last_seen', { mode: 'timestamp_ms' }).notNull().default(now),
  },
  (t) => [
    unique('subdomains_domain_host_uq').on(t.domainId, t.host),
    // Supports listUnprobed (domain_id + probed_at IS NULL), run every discovery.
    index('subdomains_domain_probed_idx').on(t.domainId, t.probedAt),
  ],
)

// --- Jobs --------------------------------------------------------------------

export const jobs = sqliteTable(
  'jobs',
  {
    id: integer('id').primaryKey({ autoIncrement: true }),
    type: text('type').notNull(),
    // 'queued' | 'running' | 'done' | 'error' | 'cancelled' | 'dead'
    // 'dead' = a stale/exhausted job we deliberately refuse to auto-resume
    // (loud active scan interrupted mid-run, or too many crash re-queues).
    status: text('status').notNull().default('queued'),
    params: text('params'), // JSON
    result: text('result'), // JSON
    error: text('error'),
    // Coarse human progress line a long handler writes as it works (e.g.
    // "probing 40/120 hosts"), bumped with updatedAt so the UI can tell a slow
    // job from a wedged one before the 20-min timeout.
    progress: text('progress'),
    // Owning domain (denormalized from params) so we can dedup pending jobs and
    // cool down per-target scans with an indexed lookup. Nullable, no FK: job
    // history must survive its domain being deleted.
    domainId: integer('domain_id'),
    // Bumped on every claim. Powers the crash-loop guard: a job that keeps
    // dying is dead-lettered instead of re-queued forever.
    attempts: integer('attempts').notNull().default(0),
    // Durable cancel request. Set when an operator cancels a running job, so the
    // intent survives a restart: on reboot a still-'running' cancelled job is
    // marked cancelled instead of being re-queued/re-run (in-memory cancel state
    // alone was lost on restart — audit §5).
    cancelRequested: integer('cancel_requested', { mode: 'boolean' }).notNull().default(false),
    createdAt: integer('created_at', { mode: 'timestamp_ms' }).notNull().default(now),
    startedAt: integer('started_at', { mode: 'timestamp_ms' }),
    finishedAt: integer('finished_at', { mode: 'timestamp_ms' }),
    updatedAt: integer('updated_at', { mode: 'timestamp_ms' }).notNull().default(now),
  },
  (t) => [
    // Supports claimNextQueued() (WHERE status='queued' ORDER BY id) on every poll.
    index('jobs_status_id_idx').on(t.status, t.id),
    // Supports hasPendingJob(type, domainId) and per-target scan cooldown.
    index('jobs_domain_type_idx').on(t.domainId, t.type, t.status),
  ],
)

// --- Findings / notes / drawings --------------------------------------------

export const findings = sqliteTable(
  'findings',
  {
    id: integer('id').primaryKey({ autoIncrement: true }),
    domainId: integer('domain_id').references(() => domains.id, { onDelete: 'cascade' }),
    type: text('type').notNull(),
    data: text('data'), // JSON
    score: integer('score'),
    tags: text('tags'), // JSON array
    // Triage lifecycle: open | confirmed | false_positive | resolved | ignored.
    status: text('status').notNull().default('open'),
    note: text('note'), // operator triage note
    // Typed correlation columns (additive; derived on write). severity is the ONE
    // canonical bucket for the score so the report and its snapshot summary agree;
    // host/ip/url are the join keys correlation needs promoted out of the JSON
    // blob; jobId links a finding to the scan that produced it.
    severity: text('severity'), // critical | high | medium | low | info
    host: text('host'),
    ip: text('ip'),
    url: text('url'),
    jobId: integer('job_id').references(() => jobs.id, { onDelete: 'set null' }),
    // Stable identity per logical finding (host/ip/url/...) so re-scans update
    // the same row instead of inserting duplicates.
    dedupeKey: text('dedupe_key'),
    // createdAt is the FIRST-SEEN timestamp: set once on insert and never touched
    // by the re-scan upsert (see findings/store.ts). lastSeenAt is refreshed on
    // every upsert, so (createdAt, lastSeenAt) give discovery age + freshness,
    // which powers monitoring diffs, report timelines, and change alerts.
    createdAt: integer('created_at', { mode: 'timestamp_ms' }).notNull().default(now),
    lastSeenAt: integer('last_seen_at', { mode: 'timestamp_ms' }),
  },
  // Supports listFindings() and the dedupe upsert lookup.
  (t) => [
    index('findings_domain_idx').on(t.domainId),
    index('findings_score_idx').on(t.score, t.createdAt),
    index('findings_dedupe_idx').on(t.domainId, t.type, t.dedupeKey),
    index('findings_status_idx').on(t.status),
    index('findings_type_idx').on(t.type),
  ],
)

// Per-asset CVE ledger powering the "new CVE on a known asset" watch. Every CVE
// ever seen on an (domain, ip) is recorded once; a scan that turns up a CVE not
// already here — on an asset that already had a baseline — is a genuine NEW
// exposure, which fires a critical finding + alert. The first scan of an asset
// just baselines (no alert on initial discovery).
export const assetCves = sqliteTable(
  'asset_cves',
  {
    id: integer('id').primaryKey({ autoIncrement: true }),
    domainId: integer('domain_id'),
    ip: text('ip').notNull(),
    cveId: text('cve_id').notNull(),
    cvss: real('cvss'),
    kev: integer('kev', { mode: 'boolean' }).notNull().default(false),
    firstSeenAt: integer('first_seen_at', { mode: 'timestamp_ms' }).notNull().default(now),
    // When the "new CVE" alert for this row was fired. NULL = recorded but not yet
    // alerted, so it is re-driven on the next run — this is what keeps a crash
    // between recording the CVE and sending its alert from losing the alert.
    // Baseline rows (first scan of an asset) are inserted already-marked so they
    // never alert.
    alertedAt: integer('alerted_at', { mode: 'timestamp_ms' }),
  },
  (t) => [
    unique('asset_cve_uq').on(t.domainId, t.ip, t.cveId),
    index('asset_cve_asset_idx').on(t.domainId, t.ip),
  ],
)

// Manual overrides for methodology steps: an operator can mark a step 'done'
// (covered even if no job/finding proves it) or 'skipped' (excluded from the
// skill's coverage denominator). Absence of a row = purely auto-derived status.
export const skillStepState = sqliteTable(
  'skill_step_state',
  {
    id: integer('id').primaryKey({ autoIncrement: true }),
    domainId: integer('domain_id').notNull(),
    skillId: text('skill_id').notNull(),
    stepKey: text('step_key').notNull(),
    state: text('state').notNull(), // 'done' | 'skipped'
    updatedAt: integer('updated_at', { mode: 'timestamp_ms' }).notNull().default(now),
  },
  (t) => [unique('skill_step_uq').on(t.domainId, t.skillId, t.stepKey)],
)

// Immutable, frozen engagement reports. A snapshot captures the full Markdown +
// HTML report AS OF a point in time, so later re-scans never mutate what a
// delivered report says. Content is stored verbatim; only the row's existence is
// mutable (delete). host is denormalised so the snapshot survives domain edits.
export const reportSnapshots = sqliteTable(
  'report_snapshots',
  {
    id: integer('id').primaryKey({ autoIncrement: true }),
    domainId: integer('domain_id').references(() => domains.id, { onDelete: 'cascade' }),
    host: text('host').notNull(),
    label: text('label'),
    contentMd: text('content_md').notNull(),
    contentHtml: text('content_html').notNull(),
    meta: text('meta'), // JSON: { findings, high, medium, low, cves }
    createdAt: integer('created_at', { mode: 'timestamp_ms' }).notNull().default(now),
  },
  (t) => [index('report_snapshot_domain_idx').on(t.domainId)],
)

export const notes = sqliteTable('notes', {
  id: integer('id').primaryKey({ autoIncrement: true }),
  // null => global note
  domainId: integer('domain_id').references(() => domains.id, { onDelete: 'set null' }),
  title: text('title'),
  body: text('body'),
  createdAt: integer('created_at', { mode: 'timestamp_ms' }).notNull().default(now),
  updatedAt: integer('updated_at', { mode: 'timestamp_ms' }).notNull().default(now),
})

export const drawings = sqliteTable('drawings', {
  id: integer('id').primaryKey({ autoIncrement: true }),
  domainId: integer('domain_id').references(() => domains.id, { onDelete: 'set null' }),
  name: text('name'),
  data: text('data'), // JSON (Excalidraw scene)
  createdAt: integer('created_at', { mode: 'timestamp_ms' }).notNull().default(now),
  updatedAt: integer('updated_at', { mode: 'timestamp_ms' }).notNull().default(now),
})

// Requests captured by the browser extension for a target, awaiting replay/review.
// Passive record only — the operator explicitly re-sends via the Replay tool.
export const capturedRequests = sqliteTable(
  'captured_requests',
  {
    id: integer('id').primaryKey({ autoIncrement: true }),
    domainId: integer('domain_id').references(() => domains.id, { onDelete: 'cascade' }),
    method: text('method').notNull(),
    url: text('url').notNull(),
    host: text('host').notNull(),
    headers: text('headers'), // JSON: [ [name, value], … ] (order preserved)
    body: text('body'),
    source: text('source').notNull().default('extension'),
    createdAt: integer('created_at', { mode: 'timestamp_ms' }).notNull().default(now),
  },
  (t) => [index('captured_domain_idx').on(t.domainId), index('captured_created_idx').on(t.createdAt)],
)

// Named request identities (A / B / anonymous) reusable across Repeater, Intruder
// and authz_diff, so credentials are defined ONCE instead of re-typed per run.
// `headers` is a JSON map { Name: Value } merged onto the outgoing request;
// `isAnon` marks a credential-stripped identity (headers usually empty).
export const identities = sqliteTable(
  'identities',
  {
    id: integer('id').primaryKey({ autoIncrement: true }),
    domainId: integer('domain_id').references(() => domains.id, { onDelete: 'cascade' }),
    name: text('name').notNull(),
    headers: text('headers').notNull().default('{}'), // JSON { name: value }
    isAnon: integer('is_anon', { mode: 'boolean' }).notNull().default(false),
    createdAt: integer('created_at', { mode: 'timestamp_ms' }).notNull().default(now),
    updatedAt: integer('updated_at', { mode: 'timestamp_ms' }).notNull().default(now),
  },
  (t) => [unique('identities_domain_name_uq').on(t.domainId, t.name), index('identities_domain_idx').on(t.domainId)],
)

// Repeater history: one row per request sent from the Replay tool, with its
// response, so the operator can revisit/re-send past requests (Caido-style).
export const replayHistory = sqliteTable(
  'replay_history',
  {
    id: integer('id').primaryKey({ autoIncrement: true }),
    domainId: integer('domain_id').references(() => domains.id, { onDelete: 'cascade' }),
    identityId: integer('identity_id').references(() => identities.id, { onDelete: 'set null' }), // which named identity sent it
    method: text('method').notNull(),
    url: text('url').notNull(),
    reqHeaders: text('req_headers'), // JSON [ [name, value], … ]
    reqBody: text('req_body'),
    status: integer('status'),
    statusText: text('status_text'),
    timeMs: integer('time_ms'),
    respBytes: integer('resp_bytes'),
    respHeaders: text('resp_headers'), // JSON [ [name, value], … ]
    respBody: text('resp_body'), // capped
    createdAt: integer('created_at', { mode: 'timestamp_ms' }).notNull().default(now),
  },
  (t) => [index('replay_history_domain_idx').on(t.domainId)],
)

// Operator-defined payload sets for the Intruder/Repeater (custom fuzz lists).
// Built-in sets ship in code (replay/payloads/builtins.ts); this table holds only
// the user's own lists — DB-backed, so no filesystem path-traversal surface.
export const payloadSets = sqliteTable(
  'payload_sets',
  {
    id: integer('id').primaryKey({ autoIncrement: true }),
    name: text('name').notNull(),
    category: text('category'), // free-form group label (xss, sqli, custom, …)
    payloads: text('payloads').notNull(), // JSON string[]
    createdAt: integer('created_at', { mode: 'timestamp_ms' }).notNull().default(now),
    updatedAt: integer('updated_at', { mode: 'timestamp_ms' }).notNull().default(now),
  },
  (t) => [unique('payload_sets_name_uq').on(t.name)],
)

// Session-wide request-rewrite rules for the Repeater/Intruder (inject an auth
// header, swap a CSRF token, rewrite Host, …). domain_id null = a global rule.
export const matchReplaceRules = sqliteTable(
  'match_replace_rules',
  {
    id: integer('id').primaryKey({ autoIncrement: true }),
    domainId: integer('domain_id').references(() => domains.id, { onDelete: 'cascade' }), // null = global
    name: text('name').notNull(),
    enabled: integer('enabled', { mode: 'boolean' }).notNull().default(true),
    part: text('part').notNull(), // 'url' | 'header' | 'body'
    match: text('match').notNull().default(''),
    replace: text('replace').notNull().default(''),
    isRegex: integer('is_regex', { mode: 'boolean' }).notNull().default(false),
    createdAt: integer('created_at', { mode: 'timestamp_ms' }).notNull().default(now),
    updatedAt: integer('updated_at', { mode: 'timestamp_ms' }).notNull().default(now),
  },
  (t) => [index('match_replace_domain_idx').on(t.domainId)],
)

// The full passive URL corpus for a domain (Wayback / Common Crawl / urlscan /
// OTX). Previously only ~50 URLs per source survived in a finding blob; persisting
// every URL here feeds JS-recon, parameter discovery and the OWASP checks the whole
// attack surface instead of ~1% of it. One row per (domain, url).
export const urlCorpus = sqliteTable(
  'url_corpus',
  {
    id: integer('id').primaryKey({ autoIncrement: true }),
    domainId: integer('domain_id').references(() => domains.id, { onDelete: 'cascade' }),
    url: text('url').notNull(),
    host: text('host'),
    source: text('source').notNull(), // wayback | commoncrawl | urlscan | otx
    firstSeen: integer('first_seen', { mode: 'timestamp_ms' }).notNull().default(now),
  },
  (t) => [unique('url_corpus_domain_url_uq').on(t.domainId, t.url), index('url_corpus_domain_idx').on(t.domainId)],
)

// Durable asset inventory. correlateDomain() used to rebuild the host->IP->port->
// CVE graph from finding JSON blobs on every request and throw it away; persisting
// it here makes an asset indexable, diffable over time, linkable and clickable.
// One row per (domain, kind, value): kind 'ip' = an address (with asn/cdn), 'host'
// = a hostname (with its resolved ip), 'service' = an ip:port.
export const assets = sqliteTable(
  'assets',
  {
    id: integer('id').primaryKey({ autoIncrement: true }),
    domainId: integer('domain_id').references(() => domains.id, { onDelete: 'cascade' }),
    kind: text('kind').notNull(), // host | ip | service
    value: text('value').notNull(),
    ip: text('ip'), // the owning/resolved IP (for host + service assets)
    port: integer('port'), // for service assets
    asn: text('asn'),
    asnName: text('asn_name'),
    cdn: text('cdn'),
    firstSeen: integer('first_seen', { mode: 'timestamp_ms' }).notNull().default(now),
    lastSeen: integer('last_seen', { mode: 'timestamp_ms' }).notNull().default(now),
  },
  (t) => [unique('assets_domain_kind_value_uq').on(t.domainId, t.kind, t.value), index('assets_domain_idx').on(t.domainId), index('assets_ip_idx').on(t.ip)],
)

// Many-to-many link between an asset and the findings that mention it.
export const assetFindings = sqliteTable(
  'asset_findings',
  {
    id: integer('id').primaryKey({ autoIncrement: true }),
    assetId: integer('asset_id').notNull().references(() => assets.id, { onDelete: 'cascade' }),
    findingId: integer('finding_id').notNull().references(() => findings.id, { onDelete: 'cascade' }),
  },
  (t) => [unique('asset_findings_uq').on(t.assetId, t.findingId), index('asset_findings_asset_idx').on(t.assetId)],
)

// Relational edges between findings. Nothing linked related findings before, so
// the UI collapsed them by naming convention (e.g. a CVE-verify PoC and the
// cve_new it confirms). A typed edge makes the relationship queryable: 'confirms'
// (a PoC proves another finding), 'evidence_for', 'same_asset', 'chained_from'.
export const findingLinks = sqliteTable(
  'finding_links',
  {
    id: integer('id').primaryKey({ autoIncrement: true }),
    fromId: integer('from_id').notNull().references(() => findings.id, { onDelete: 'cascade' }),
    toId: integer('to_id').notNull().references(() => findings.id, { onDelete: 'cascade' }),
    kind: text('kind').notNull(), // confirms | evidence_for | same_asset | chained_from
    createdAt: integer('created_at', { mode: 'timestamp_ms' }).notNull().default(now),
  },
  (t) => [unique('finding_links_uq').on(t.fromId, t.toId, t.kind), index('finding_links_to_idx').on(t.toId), index('finding_links_from_idx').on(t.fromId)],
)

export type User = typeof users.$inferSelect
export type PayloadSet = typeof payloadSets.$inferSelect
export type MatchReplaceRuleRow = typeof matchReplaceRules.$inferSelect
export type UrlCorpusRow = typeof urlCorpus.$inferSelect
export type AssetRow = typeof assets.$inferSelect
export type FindingLinkRow = typeof findingLinks.$inferSelect
export type IdentityRow = typeof identities.$inferSelect
export type Domain = typeof domains.$inferSelect
export type CapturedRequest = typeof capturedRequests.$inferSelect
export type ReplayHistoryRow = typeof replayHistory.$inferSelect
export type Subdomain = typeof subdomains.$inferSelect
export type Job = typeof jobs.$inferSelect
export type AuditEntry = typeof auditLog.$inferSelect
