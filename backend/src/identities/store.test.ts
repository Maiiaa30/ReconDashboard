import { describe, expect, it, vi } from 'vitest'

// Real in-memory DB (just the identities table) so we exercise the actual
// insert/update/dedup SQL. The store only uses the core query builder.
vi.mock('../db/index', async () => {
  const Database = (await import('better-sqlite3')).default
  const { drizzle } = await import('drizzle-orm/better-sqlite3')
  const sqlite = new Database(':memory:')
  sqlite.exec(`
    CREATE TABLE identities (
      id integer PRIMARY KEY AUTOINCREMENT,
      domain_id integer,
      name text NOT NULL,
      headers text NOT NULL DEFAULT '{}',
      is_anon integer NOT NULL DEFAULT 0,
      created_at integer NOT NULL DEFAULT 0,
      updated_at integer NOT NULL DEFAULT 0
    );
    CREATE UNIQUE INDEX identities_domain_name_uq ON identities (domain_id, name);
  `)
  return { db: drizzle(sqlite), sqlite }
})

import { deleteIdentity, identityHeadersFor, listIdentities, upsertIdentity } from './store'

describe('identities store', () => {
  it('creates and reads back an identity with parsed headers', () => {
    const idn = upsertIdentity({ domainId: 1, name: 'admin', headers: { Authorization: 'Bearer AAA', 'X-Env': 'prod' } })
    expect(idn.name).toBe('admin')
    expect(idn.headers.Authorization).toBe('Bearer AAA')
    expect(listIdentities(1).map((i) => i.name)).toContain('admin')
  })

  it('upserts by (domain, name) — re-saving edits, not duplicates', () => {
    upsertIdentity({ domainId: 2, name: 'userB', headers: { Cookie: 'a=1' } })
    upsertIdentity({ domainId: 2, name: 'userB', headers: { Cookie: 'a=2' } })
    const rows = listIdentities(2).filter((i) => i.name === 'userB')
    expect(rows.length).toBe(1)
    expect(rows[0].headers.Cookie).toBe('a=2')
  })

  it('scopes identities per domain and guards cross-domain resolution', () => {
    const a = upsertIdentity({ domainId: 3, name: 'x', headers: { A: '1' } })
    expect(identityHeadersFor(a.id, 3)?.headers.A).toBe('1')
    expect(identityHeadersFor(a.id, 99)).toBeNull() // wrong domain
  })

  it('marks an anonymous identity and drops non-string / oversized headers', () => {
    const anon = upsertIdentity({ domainId: 4, name: 'anon', isAnon: true, headers: { Bad: 123 as unknown as string, Ok: 'y' } })
    expect(anon.isAnon).toBe(true)
    expect(anon.headers.Bad).toBeUndefined()
    expect(anon.headers.Ok).toBe('y')
  })

  it('deletes an identity', () => {
    const idn = upsertIdentity({ domainId: 5, name: 'temp' })
    expect(deleteIdentity(idn.id)).toBe(true)
    expect(listIdentities(5)).toEqual([])
  })
})
