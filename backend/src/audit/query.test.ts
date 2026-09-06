import { describe, expect, it, vi } from 'vitest'

// Real in-memory audit_log so the SQL filters, the keyset ORDER BY, and the
// GROUP BY counts are actually exercised (mirrors findings/query.test.ts). The id
// is a monotonic autoincrement, so the unfiltered order is strictly [5,4,3,2,1].
// `ts` is set apart from `id` order deliberately so a `since` filter can't be
// satisfied by id alone.
vi.mock('../db/index', async () => {
  const Database = (await import('better-sqlite3')).default
  const { drizzle } = await import('drizzle-orm/better-sqlite3')
  const sqlite = new Database(':memory:')
  sqlite.exec(`
    CREATE TABLE audit_log (
      id integer PRIMARY KEY AUTOINCREMENT,
      ts integer NOT NULL DEFAULT 0,
      actor text NOT NULL,
      action text NOT NULL,
      domain_id integer,
      target text,
      mode text,
      job_id integer,
      detail text
    );
  `)
  sqlite.exec(`
    INSERT INTO audit_log (id, ts, actor, action, domain_id, target, mode) VALUES
      (1, 1000, 'maia',   'enqueue:nmap_scan', 7, 'a.example.com', 'active'),
      (2, 2000, 'maia',   'job:start',         7, 'a.example.com', 'active'),
      (3, 3000, 'worker', 'job:done',          7, 'a.example.com', 'active'),
      (4, 4000, 'maia',   'enqueue:nmap_scan', 8, 'b_test.com',    'passive'),
      (5, 5000, 'worker', 'job:done',          8, 'b_test.com',    'passive');
  `)
  return { db: drizzle(sqlite), sqlite }
})

import { queryAudit, summarizeAudit } from './store'

const ids = (r: { entries: { id: number }[] }) => r.entries.map((e) => e.id)

describe('queryAudit', () => {
  it('orders newest-first by the monotonic primary key', () => {
    expect(ids(queryAudit())).toEqual([5, 4, 3, 2, 1])
  })

  it('pages with a keyset cursor, covering every row exactly once', () => {
    const p1 = queryAudit({ limit: 2 })
    expect(ids(p1)).toEqual([5, 4])
    expect(p1.nextCursor).not.toBeNull()

    const p2 = queryAudit({ limit: 2, cursor: p1.nextCursor! })
    expect(ids(p2)).toEqual([3, 2])

    const p3 = queryAudit({ limit: 2, cursor: p2.nextCursor! })
    expect(ids(p3)).toEqual([1])
    // Last page has no next cursor.
    expect(p3.nextCursor).toBeNull()
  })

  it('returns null nextCursor when the page exactly drains the table', () => {
    const p = queryAudit({ limit: 5 })
    expect(ids(p)).toEqual([5, 4, 3, 2, 1])
    expect(p.nextCursor).toBeNull()
  })

  it('filters by domain', () => {
    expect(ids(queryAudit({ domainId: 8 }))).toEqual([5, 4])
  })

  it('filters by exact actor and action', () => {
    expect(ids(queryAudit({ actor: 'worker' }))).toEqual([5, 3])
    expect(ids(queryAudit({ action: 'enqueue:nmap_scan' }))).toEqual([4, 1])
  })

  it('filters by mode', () => {
    expect(ids(queryAudit({ mode: 'passive' }))).toEqual([5, 4])
  })

  it('filters by target substring', () => {
    expect(ids(queryAudit({ target: 'a.example' }))).toEqual([3, 2, 1])
  })

  it('treats a literal % / _ in the target as text, not a wildcard', () => {
    // '_' would match any char if not escaped; only the b_test rows contain it.
    expect(ids(queryAudit({ target: 'b_test' }))).toEqual([5, 4])
    // A bare '%' must match nothing (no target literally contains a percent sign).
    expect(ids(queryAudit({ target: '%' }))).toEqual([])
  })

  it('filters by since (exclusive) on the timestamp, not the id', () => {
    expect(ids(queryAudit({ since: new Date(3000) }))).toEqual([5, 4])
  })

  it('ignores a garbled or out-of-range cursor (restarts from the top)', () => {
    expect(ids(queryAudit({ cursor: 'not-a-number' }))).toEqual([5, 4, 3, 2, 1])
    expect(ids(queryAudit({ cursor: '-1' }))).toEqual([5, 4, 3, 2, 1])
    expect(ids(queryAudit({ cursor: '0' }))).toEqual([5, 4, 3, 2, 1])
  })
})

describe('summarizeAudit', () => {
  it('counts total and per-action across the whole table', () => {
    const s = summarizeAudit()
    expect(s.total).toBe(5)
    expect(s.byAction).toEqual({ 'enqueue:nmap_scan': 2, 'job:start': 1, 'job:done': 2 })
  })

  it('applies the shared facets but never the action facet', () => {
    const s = summarizeAudit({ domainId: 7 })
    expect(s.total).toBe(3)
    expect(s.byAction).toEqual({ 'enqueue:nmap_scan': 1, 'job:start': 1, 'job:done': 1 })
  })
})
