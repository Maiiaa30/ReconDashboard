// Drizzle ORM schema (SQLite).
//
// Timestamps are stored as integer epoch milliseconds (mode: 'timestamp_ms'),
// so Drizzle hands back JS Date objects. Booleans are integer 0/1.

import { sql } from 'drizzle-orm'
import { index, integer, sqliteTable, text, unique } from 'drizzle-orm/sqlite-core'

const now = sql`(unixepoch() * 1000)`

// --- Auth --------------------------------------------------------------------

export const users = sqliteTable('users', {
  id: integer('id').primaryKey({ autoIncrement: true }),
  username: text('username').notNull().unique(),
  passwordHash: text('password_hash').notNull(),
  // TOTP secret is generated at seed time; 2FA stays disabled until enabled.
  totpSecret: text('totp_secret').notNull(),
  totpEnabled: integer('totp_enabled', { mode: 'boolean' }).notNull().default(false),
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
  createdAt: integer('created_at', { mode: 'timestamp_ms' }).notNull().default(now),
  updatedAt: integer('updated_at', { mode: 'timestamp_ms' }).notNull().default(now),
})

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
    firstSeen: integer('first_seen', { mode: 'timestamp_ms' }).notNull().default(now),
    lastSeen: integer('last_seen', { mode: 'timestamp_ms' }).notNull().default(now),
  },
  (t) => [unique('subdomains_domain_host_uq').on(t.domainId, t.host)],
)

// --- Jobs --------------------------------------------------------------------

export const jobs = sqliteTable(
  'jobs',
  {
    id: integer('id').primaryKey({ autoIncrement: true }),
    type: text('type').notNull(),
    // 'queued' | 'running' | 'done' | 'error'
    status: text('status').notNull().default('queued'),
    params: text('params'), // JSON
    result: text('result'), // JSON
    error: text('error'),
    createdAt: integer('created_at', { mode: 'timestamp_ms' }).notNull().default(now),
    startedAt: integer('started_at', { mode: 'timestamp_ms' }),
    finishedAt: integer('finished_at', { mode: 'timestamp_ms' }),
    updatedAt: integer('updated_at', { mode: 'timestamp_ms' }).notNull().default(now),
  },
  // Supports claimNextQueued() (WHERE status='queued' ORDER BY id) on every poll.
  (t) => [index('jobs_status_id_idx').on(t.status, t.id)],
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
    createdAt: integer('created_at', { mode: 'timestamp_ms' }).notNull().default(now),
  },
  // Supports listFindings(): filter by domain/type, ORDER BY score DESC, created DESC.
  (t) => [index('findings_domain_idx').on(t.domainId), index('findings_score_idx').on(t.score, t.createdAt)],
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
