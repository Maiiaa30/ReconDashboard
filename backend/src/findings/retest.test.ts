import { describe, expect, it, vi } from 'vitest'

// Real in-memory findings table so the retest lifecycle (requestRetest, the
// upsert-driven auto-resolution, and the triage stamp-clearing) is exercised
// against actual SQL.
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
      dedupe_key text, created_at integer NOT NULL DEFAULT 0, last_seen_at integer,
      retest_requested_at integer
    );
  `)
  return { db: drizzle(sqlite), sqlite }
})

import { addFinding, getFinding, requestRetest, updateFindingTriage } from './store'

// Seed a confirmed finding and return its id.
function seedConfirmed(host: string): number {
  const id = addFinding({ domainId: 7, type: 'new_subdomain', data: { host }, score: 50 })
  updateFindingTriage(id, { status: 'confirmed' })
  return id
}

describe('retest lifecycle', () => {
  it('requestRetest moves a finding to retest_pending and stamps when', () => {
    const id = seedConfirmed('a.example.com')
    expect(requestRetest(id)).toBe(true)
    const f = getFinding(id)!
    expect(f.status).toBe('retest_pending')
    expect(f.retestRequestedAt).toBeInstanceOf(Date)
  })

  it('re-detecting a pending finding flips it back to confirmed and clears the stamp', () => {
    const id = seedConfirmed('b.example.com')
    requestRetest(id)
    // A later scan re-observes the same host (same dedupe key) → still present.
    const sameId = addFinding({ domainId: 7, type: 'new_subdomain', data: { host: 'b.example.com' }, score: 55 })
    expect(sameId).toBe(id) // upsert, not a new row
    const f = getFinding(id)!
    expect(f.status).toBe('confirmed')
    expect(f.retestRequestedAt).toBeNull()
  })

  it('re-detecting a finding marked fixed (retest_passed) reopens it', () => {
    const id = seedConfirmed('c.example.com')
    updateFindingTriage(id, { status: 'retest_passed' })
    addFinding({ domainId: 7, type: 'new_subdomain', data: { host: 'c.example.com' } })
    expect(getFinding(id)!.status).toBe('open')
  })

  it('setting any non-pending status clears the awaiting-retest stamp', () => {
    const id = seedConfirmed('d.example.com')
    requestRetest(id)
    expect(getFinding(id)!.retestRequestedAt).toBeInstanceOf(Date)
    updateFindingTriage(id, { status: 'retest_passed' })
    expect(getFinding(id)!.retestRequestedAt).toBeNull()
  })

  it('re-detecting a normal open/confirmed finding leaves its status untouched', () => {
    const id = seedConfirmed('e.example.com')
    addFinding({ domainId: 7, type: 'new_subdomain', data: { host: 'e.example.com' }, score: 60 })
    expect(getFinding(id)!.status).toBe('confirmed')
  })
})
