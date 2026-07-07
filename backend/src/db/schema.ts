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
  // Persisted per-operator UI state so the selected target follows the account
  // across browsers/devices (not just this browser's localStorage).
  selectedDomainId: integer('selected_domain_id'),
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

export type User = typeof users.$inferSelect
export type Domain = typeof domains.$inferSelect
export type Subdomain = typeof subdomains.$inferSelect
export type Job = typeof jobs.$inferSelect
export type AuditEntry = typeof auditLog.$inferSelect
