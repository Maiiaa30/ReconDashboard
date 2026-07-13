import { rm } from 'node:fs/promises'
import { desc, eq } from 'drizzle-orm'
import { db } from '../db/index'
import {
  domains,
  findings,
  subdomains,
  jobs,
  assetCves,
  skillStepState,
  reportSnapshots,
  capturedRequests,
  replayHistory,
} from '../db/schema'
import { isValidDomain, normalizeDomain } from '../util/validate'
import { screenshotDirFor } from '../util/screenshotPaths'
import { invalidateDomainOverviews } from './overview'

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
  invalidateDomainOverviews()
  return getDomain(Number(res.lastInsertRowid))
}

export function updateDomainMode(id: number, mode: DomainMode) {
  db.update(domains).set({ mode, updatedAt: new Date() }).where(eq(domains.id, id)).run()
  invalidateDomainOverviews()
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
    scopeConfig?: unknown
    authorizedFrom?: number | null
    authorizedUntil?: number | null
  },
) {
  const set: Record<string, unknown> = { updatedAt: new Date() }
  if (patch.mode === 'passive_only' || patch.mode === 'active_authorized') set.mode = patch.mode
  if (patch.label !== undefined) set.label = patch.label?.toString().trim() || null
  if (patch.profile !== undefined) set.profile = JSON.stringify(patch.profile ?? {})
  if (patch.owaspConfig !== undefined) set.owaspConfig = JSON.stringify(patch.owaspConfig ?? {})
  if (patch.scopeConfig !== undefined) set.scopeConfig = JSON.stringify(patch.scopeConfig ?? {})
  if (patch.authorizedFrom !== undefined) {
    set.authorizedFrom = toDateOrNull(patch.authorizedFrom)
  }
  if (patch.authorizedUntil !== undefined) {
    set.authorizedUntil = toDateOrNull(patch.authorizedUntil)
  }
  if (patch.monitorIntervalHours !== undefined) {
    const h = Math.trunc(Number(patch.monitorIntervalHours))
    set.monitorIntervalHours = Number.isFinite(h) && h > 0 ? Math.min(h, 168) : 0
  }
  db.update(domains).set(set).where(eq(domains.id, id)).run()
  invalidateDomainOverviews()
  return getDomain(id)
}

// Accept an epoch-ms number (or null/0 to clear) and return a Date for storage.
function toDateOrNull(v: number | null): Date | null {
  if (v == null) return null
  const n = Number(v)
  return Number.isFinite(n) && n > 0 ? new Date(n) : null
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

// Delete every domain-scoped recon record for a domain WITHOUT removing the
// domain itself — a reset. Keeps the domain row + its config, the operator's
// notes/drawings, and the audit ledger. Explicit per-table deletes (not just FK
// cascade) so tables without a cascade FK — subdomains, jobs, asset_cves,
// skill_step_state — are cleared too.
export async function purgeDomainData(id: number): Promise<void> {
  db.transaction((tx) => {
    tx.delete(findings).where(eq(findings.domainId, id)).run()
    tx.delete(subdomains).where(eq(subdomains.domainId, id)).run()
    tx.delete(jobs).where(eq(jobs.domainId, id)).run()
    tx.delete(assetCves).where(eq(assetCves.domainId, id)).run()
    tx.delete(skillStepState).where(eq(skillStepState.domainId, id)).run()
    tx.delete(reportSnapshots).where(eq(reportSnapshots.domainId, id)).run()
    tx.delete(capturedRequests).where(eq(capturedRequests.domainId, id)).run()
    tx.delete(replayHistory).where(eq(replayHistory.domainId, id)).run()
  })
  invalidateDomainOverviews()
  await rm(screenshotDirFor(id), { recursive: true, force: true }).catch(() => {})
}

export async function deleteDomain(id: number): Promise<void> {
  await purgeDomainData(id) // also clears the tables the domain FK doesn't cascade
  db.delete(domains).where(eq(domains.id, id)).run()
  invalidateDomainOverviews()
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
