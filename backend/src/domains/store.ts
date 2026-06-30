import { desc, eq } from 'drizzle-orm'
import { db } from '../db/index'
import { domains } from '../db/schema'
import { isValidDomain, normalizeDomain } from '../util/validate'

export type DomainMode = 'passive_only' | 'active_authorized'

export class DomainValidationError extends Error {}

export function listDomains() {
  return db.select().from(domains).orderBy(desc(domains.id)).all()
}

export function getDomain(id: number) {
  return db.select().from(domains).where(eq(domains.id, id)).limit(1).all()[0]
}

export function createDomain(input: { host: string; label?: string; mode?: DomainMode }) {
  const host = normalizeDomain(input.host)
  if (!isValidDomain(host)) {
    throw new DomainValidationError(`"${input.host}" is not a valid domain`)
  }
  const mode: DomainMode = input.mode === 'active_authorized' ? 'active_authorized' : 'passive_only'

  const existing = db.select().from(domains).where(eq(domains.host, host)).limit(1).all()[0]
  if (existing) throw new DomainValidationError(`domain "${host}" already exists`)

  const res = db
    .insert(domains)
    .values({ host, label: input.label?.trim() || null, mode })
    .run()
  return getDomain(Number(res.lastInsertRowid))
}

export function updateDomainMode(id: number, mode: DomainMode) {
  db.update(domains).set({ mode, updatedAt: new Date() }).where(eq(domains.id, id)).run()
  return getDomain(id)
}

export function updateDomain(
  id: number,
  patch: { mode?: DomainMode; label?: string | null; profile?: unknown },
) {
  const set: Record<string, unknown> = { updatedAt: new Date() }
  if (patch.mode === 'passive_only' || patch.mode === 'active_authorized') set.mode = patch.mode
  if (patch.label !== undefined) set.label = patch.label?.toString().trim() || null
  if (patch.profile !== undefined) set.profile = JSON.stringify(patch.profile ?? {})
  db.update(domains).set(set).where(eq(domains.id, id)).run()
  return getDomain(id)
}

export function deleteDomain(id: number): void {
  db.delete(domains).where(eq(domains.id, id)).run()
}

export function requireActiveAuthorized(id: number): void {
  const d = getDomain(id)
  if (!d) throw new DomainValidationError('domain not found')
  if (d.mode !== 'active_authorized') {
    throw new DomainValidationError(
      `domain "${d.host}" is passive_only; active/loud scans require active_authorized`,
    )
  }
}
