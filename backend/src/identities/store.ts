import { and, desc, eq } from 'drizzle-orm'
import { db } from '../db/index'
import { identities, type IdentityRow } from '../db/schema'
import { safeJsonParse } from '../util/json'

// Named request identities (A / B / anonymous), reusable across Repeater,
// Intruder and authz_diff so credentials are defined once. Headers are stored as
// a JSON { name: value } map and merged onto the outgoing request at send time.

export interface Identity {
  id: number
  domainId: number | null
  name: string
  headers: Record<string, string>
  isAnon: boolean
}

function toIdentity(r: IdentityRow): Identity {
  return { id: r.id, domainId: r.domainId, name: r.name, headers: safeJsonParse<Record<string, string>>(r.headers, {}), isAnon: r.isAnon }
}

// Keep a stored identity bounded: string keys/values only, empties dropped, count
// and per-value size capped so a pasted blob can't bloat the row.
function sanitizeHeaders(h: unknown): Record<string, string> {
  const out: Record<string, string> = {}
  if (h && typeof h === 'object') {
    for (const [k, v] of Object.entries(h as Record<string, unknown>)) {
      const name = String(k).trim()
      if (!name || typeof v !== 'string') continue
      out[name] = v.slice(0, 8192)
      if (Object.keys(out).length >= 50) break
    }
  }
  return out
}

export function listIdentities(domainId: number): Identity[] {
  return db.select().from(identities).where(eq(identities.domainId, domainId)).orderBy(desc(identities.id)).all().map(toIdentity)
}

export function getIdentity(id: number): Identity | undefined {
  const r = db.select().from(identities).where(eq(identities.id, id)).limit(1).all()[0]
  return r ? toIdentity(r) : undefined
}

// Create or update by (domainId, name) — the unique key — so re-saving a name
// edits it instead of colliding.
export function upsertIdentity(input: { domainId: number; name: string; headers?: Record<string, string>; isAnon?: boolean }): Identity {
  const name = input.name.trim().slice(0, 80)
  const headers = JSON.stringify(sanitizeHeaders(input.headers))
  const isAnon = input.isAnon === true
  const existing = db
    .select()
    .from(identities)
    .where(and(eq(identities.domainId, input.domainId), eq(identities.name, name)))
    .limit(1)
    .all()[0]
  if (existing) {
    db.update(identities).set({ headers, isAnon, updatedAt: new Date() }).where(eq(identities.id, existing.id)).run()
    return getIdentity(existing.id)!
  }
  const res = db.insert(identities).values({ domainId: input.domainId, name, headers, isAnon }).run()
  return getIdentity(Number(res.lastInsertRowid))!
}

export function deleteIdentity(id: number): boolean {
  return db.delete(identities).where(eq(identities.id, id)).run().changes > 0
}

// Resolve an identity for a domain (guards cross-domain use). Returns name +
// headers + isAnon, or null if not found / belongs to another domain.
export function identityHeadersFor(id: number, domainId: number): { name: string; headers: Record<string, string>; isAnon: boolean } | null {
  const idn = getIdentity(id)
  if (!idn || idn.domainId !== domainId) return null
  return { name: idn.name, headers: idn.headers, isAnon: idn.isAnon }
}
