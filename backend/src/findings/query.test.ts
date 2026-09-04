import { describe, expect, it, vi } from 'vitest'

// Real in-memory findings table so the SQL filters, the keyset ORDER BY, and the
// GROUP BY counts are actually exercised (mirrors links.test.ts). The rows are
// crafted for a deterministic (score desc, createdAt desc, id desc) order:
//   score: 90(1) > 80(3,2) > 50(5) > null(4, coalesced to -1, sorts last)
//   the 80-tie breaks on createdAt desc -> id3 (created 3000) before id2 (2000)
// so the full unfiltered order is [1, 3, 2, 5, 4].
vi.mock('../db/index', async () => {
  const Database = (await import('better-sqlite3')).default
  const { drizzle } = await import('drizzle-orm/better-sqlite3')
  const sqlite = new Database(':memory:')
  sqlite.exec(`
    CREATE TABLE findings (
      id integer PRIMARY KEY AUTOINCREMENT,
      domain_id integer, type text NOT NULL, data text, score integer, tags text,
      status text NOT NULL DEFAULT 'open', note text,
      severity text, host text, ip text, url text, job_id integer,
      dedupe_key text, created_at integer NOT NULL DEFAULT 0, last_seen_at integer
    );
  `)
  sqlite.exec(`
    INSERT INTO findings (id, domain_id, type, data, score, tags, status, severity, host, ip, url, created_at) VALUES
      (1, 7, 'exposure',      '{}', 90, '["kev"]',   'open',      'critical', 'a.example.com', '1.1.1.1', NULL,                        1000),
      (2, 7, 'owasp',         '{}', 80, '["xss"]',   'open',      'high',     'b.example.com', NULL,      'https://b.example.com/x',    2000),
      (3, 7, 'ffuf',          '{}', 80, '["admin"]', 'confirmed', 'medium',   NULL,            NULL,      'https://a.example.com/admin',3000),
      (4, 7, 'new_subdomain', '{}', NULL,'[]',        'open',      'info',     'c.example.com', NULL,      NULL,                         4000),
      (5, 8, 'tool',          '{}', 50, '["tls"]',   'resolved',  'low',      'd.example.com', '2.2.2.2', NULL,                         5000);
  `)
  return { db: drizzle(sqlite), sqlite }
})

// jobContext (pulled in by store.ts) uses node:async_hooks — fine under vitest.
import { queryFindings, summarizeFindings } from './store'

const ids = (r: { findings: { id: number }[] }) => r.findings.map((f) => f.id)

describe('queryFindings', () => {
  it('orders by score desc, then createdAt desc, then id desc (nulls last)', () => {
    expect(ids(queryFindings())).toEqual([1, 3, 2, 5, 4])
  })

  it('pages with a keyset cursor, covering every row exactly once', () => {
    const p1 = queryFindings({ limit: 2 })
    expect(ids(p1)).toEqual([1, 3])
    expect(p1.nextCursor).toBeTruthy()

    const p2 = queryFindings({ limit: 2, cursor: p1.nextCursor! })
    expect(ids(p2)).toEqual([2, 5])
    expect(p2.nextCursor).toBeTruthy()

    const p3 = queryFindings({ limit: 2, cursor: p2.nextCursor! })
    expect(ids(p3)).toEqual([4])
    expect(p3.nextCursor).toBeNull() // last page

    expect([...ids(p1), ...ids(p2), ...ids(p3)]).toEqual([1, 3, 2, 5, 4])
  })

  it('restarts from the top on a garbled cursor instead of throwing', () => {
    expect(ids(queryFindings({ cursor: 'not-a-real-cursor' }))).toEqual([1, 3, 2, 5, 4])
  })

  it('active status excludes triaged-away findings; all keeps them', () => {
    expect(ids(queryFindings({ status: 'active' }))).toEqual([1, 3, 2, 4]) // 5 is resolved
    expect(ids(queryFindings({ status: 'all' }))).toEqual([1, 3, 2, 5, 4])
    expect(ids(queryFindings({ status: 'confirmed' }))).toEqual([3])
  })

  it('filters by severity, domain, and type', () => {
    expect(ids(queryFindings({ severity: 'high' }))).toEqual([2])
    expect(ids(queryFindings({ domainId: 7 }))).toEqual([1, 3, 2, 4])
    expect(ids(queryFindings({ type: 'tool' }))).toEqual([5])
  })

  it('matches the asset substring across host, ip and url', () => {
    expect(ids(queryFindings({ asset: 'a.example.com' })).sort()).toEqual([1, 3]) // host + url
    expect(ids(queryFindings({ asset: '2.2.2.2' }))).toEqual([5]) // ip
  })

  it('matches the tag substring and the since window', () => {
    expect(ids(queryFindings({ tag: 'adm' }))).toEqual([3])
    expect(ids(queryFindings({ tag: 'kev' }))).toEqual([1])
    // createdAt (ms) > 2500 -> ids 3,4,5, returned in score order.
    expect(ids(queryFindings({ since: new Date(2500) }))).toEqual([3, 5, 4])
  })

  it('treats a % in the asset term literally, not as a wildcard', () => {
    expect(ids(queryFindings({ asset: '%' }))).toEqual([]) // no host/ip/url contains a literal %
  })
})

describe('summarizeFindings', () => {
  it('counts totals and per-status/per-severity buckets over the filter set', () => {
    const all = summarizeFindings()
    expect(all.total).toBe(5)
    expect(all.byStatus).toEqual({ open: 3, confirmed: 1, resolved: 1 })
    expect(all.bySeverity).toEqual({ critical: 1, high: 1, medium: 1, low: 1, info: 1 })
  })

  it('respects the non-facet filters (domain here)', () => {
    const d7 = summarizeFindings({ domainId: 7 })
    expect(d7.total).toBe(4)
    expect(d7.byStatus).toEqual({ open: 3, confirmed: 1 })
  })
})
