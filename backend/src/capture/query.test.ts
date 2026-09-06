import { describe, expect, it, vi } from 'vitest'

// Real in-memory captured_requests table so the SQL filters, the keyset ORDER BY
// and the GROUP BY counts are actually exercised. Row 6 is another domain to
// prove the domain scope is applied. Ids are monotonic, so the unfiltered
// domain-1 order is [5,4,3,2,1].
vi.mock('../db/index', async () => {
  const Database = (await import('better-sqlite3')).default
  const { drizzle } = await import('drizzle-orm/better-sqlite3')
  const sqlite = new Database(':memory:')
  sqlite.exec(`
    CREATE TABLE captured_requests (
      id integer PRIMARY KEY AUTOINCREMENT,
      domain_id integer,
      method text NOT NULL,
      url text NOT NULL,
      host text NOT NULL,
      headers text NOT NULL DEFAULT '[]',
      body text,
      source text NOT NULL DEFAULT 'extension',
      created_at integer NOT NULL DEFAULT 0
    );
  `)
  sqlite.exec(`
    INSERT INTO captured_requests (id, domain_id, method, url, host, body, created_at) VALUES
      (1, 1, 'GET',  'https://a.example.com/',        'a.example.com', NULL,       1000),
      (2, 1, 'POST', 'https://a.example.com/login',   'a.example.com', '{"x":1}',  2000),
      (3, 1, 'GET',  'https://b.example.com/api?q=1', 'b.example.com', NULL,       3000),
      (4, 1, 'PUT',  'https://b.example.com/up_load', 'b.example.com', 'data',     4000),
      (5, 1, 'GET',  'https://c.other.com/',          'c.other.com',   NULL,       5000),
      (6, 2, 'GET',  'https://z.other.com/',          'z.other.com',   NULL,       6000);
  `)
  return { db: drizzle(sqlite), sqlite }
})

import { queryCaptures, summarizeCaptures } from './store'

const ids = (r: { captures: { id: number }[] }) => r.captures.map((c) => c.id)
const run = (q: Parameters<typeof queryCaptures>[0] = {}) => queryCaptures({ domainId: 1, ...q })

describe('queryCaptures', () => {
  it('lists newest-first, scoped to the domain, omitting the body', () => {
    const r = run()
    expect(ids(r)).toEqual([5, 4, 3, 2, 1])
    expect(r.captures.every((c) => (c as { body: string | null }).body === null)).toBe(true)
    expect((r.captures.find((c) => c.id === 2) as { hasBody: boolean }).hasBody).toBe(true)
    expect((r.captures.find((c) => c.id === 1) as { hasBody: boolean }).hasBody).toBe(false)
  })

  it('pages with a keyset cursor covering every row exactly once', () => {
    const p1 = run({ limit: 2 })
    expect(ids(p1)).toEqual([5, 4])
    const p2 = run({ limit: 2, cursor: p1.nextCursor! })
    expect(ids(p2)).toEqual([3, 2])
    const p3 = run({ limit: 2, cursor: p2.nextCursor! })
    expect(ids(p3)).toEqual([1])
    expect(p3.nextCursor).toBeNull()
  })

  it('filters by exact method (case-insensitive)', () => {
    expect(ids(run({ method: 'get' }))).toEqual([5, 3, 1])
  })

  it('free-text q matches host, url or method', () => {
    expect(ids(run({ q: 'login' }))).toEqual([2]) // url
    expect(ids(run({ q: 'example' }))).toEqual([4, 3, 2, 1]) // host
    expect(ids(run({ q: 'post' }))).toEqual([2]) // method
  })

  it('treats a literal _ in q as text, not a wildcard', () => {
    expect(ids(run({ q: 'up_load' }))).toEqual([4])
    expect(ids(run({ q: '%' }))).toEqual([])
  })

  it('ignores a garbled/out-of-range cursor (restarts from the top)', () => {
    expect(ids(run({ cursor: 'not-a-number' }))).toEqual([5, 4, 3, 2, 1])
    expect(ids(run({ cursor: '0' }))).toEqual([5, 4, 3, 2, 1])
  })
})

describe('summarizeCaptures', () => {
  it('counts total and per-method for the domain', () => {
    expect(summarizeCaptures({ domainId: 1 })).toEqual({ total: 5, byMethod: { GET: 3, POST: 1, PUT: 1 } })
  })

  it('applies the q filter but never the method facet', () => {
    expect(summarizeCaptures({ domainId: 1, q: 'example' })).toEqual({
      total: 4,
      byMethod: { GET: 2, POST: 1, PUT: 1 },
    })
  })
})
