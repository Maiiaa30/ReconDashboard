import { rm } from 'node:fs/promises'
import { desc, eq } from 'drizzle-orm'
import { db } from '../db/index'
import { domains } from '../db/schema'
import { isValidDomain, normalizeDomain } from '../util/validate'
import { screenshotDirFor } from '../util/screenshotPaths'

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
  patch: {
    mode?: DomainMode
    label?: string | null
    profile?: unknown
    monitorIntervalHours?: number
    owaspConfig?: unknown
  },
) {
  const set: Record<string, unknown> = { updatedAt: new Date() }
  if (patch.mode === 'passive_only' || patch.mode === 'active_authorized') set.mode = patch.mode
  if (patch.label !== undefined) set.label = patch.label?.toString().trim() || null
  if (patch.profile !== undefined) set.profile = JSON.stringify(patch.profile ?? {})
  if (patch.owaspConfig !== undefined) set.owaspConfig = JSON.stringify(patch.owaspConfig ?? {})
  if (patch.monitorIntervalHours !== undefined) {
    const h = Math.trunc(Number(patch.monitorIntervalHours))
    set.monitorIntervalHours = Number.isFinite(h) && h > 0 ? Math.min(h, 168) : 0
  }
  db.update(domains).set(set).where(eq(domains.id, id)).run()
  return getDomain(id)
}

// Domains whose auto-monitor interval has elapsed (or never ran). The first run
// fires as soon as monitoring is enabled, since lastMonitoredAt is null.
export function domainsDueForMonitoring(nowMs: number) {
  return listDomains().filter((d) => {
    if (!d.monitorIntervalHours || d.monitorIntervalHours <= 0) return false
    const last = d.lastMonitoredAt ? d.lastMonitoredAt.getTime() : 0
    return nowMs - last >= d.monitorIntervalHours * 3_600_000
  })
}

export function markMonitored(id: number, when: Date = new Date()): void {
  db.update(domains).set({ lastMonitoredAt: when }).where(eq(domains.id, id)).run()
}

export async function deleteDomain(id: number): Promise<void> {
  db.delete(domains).where(eq(domains.id, id)).run()
  // Remove orphaned screenshot files (the FK cascade only drops DB rows).
  await rm(screenshotDirFor(id), { recursive: true, force: true }).catch(() => {})
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
