import { desc, eq } from 'drizzle-orm'
import { db } from '../db/index'
import { reportSnapshots } from '../db/schema'
import { getDomain } from '../domains/store'
import { listFindings } from './store'
import { buildDomainReport, buildDomainReportHtml } from './report'
import { isHigh, severityBucket } from './severity'

export interface SnapshotMeta {
  findings: number
  high: number
  medium: number
  low: number
  cves: number
}

// Headline counts for the snapshot list, mirroring the report's severity split
// (false-positive / ignored excluded, like the report itself).
function summariseFindings(domainId: number): SnapshotMeta {
  const findings = listFindings({ domainId, limit: 5000 }).filter(
    (f) => (f as any).status !== 'false_positive' && (f as any).status !== 'ignored',
  )
  return {
    findings: findings.length,
    high: findings.filter((f) => isHigh(severityBucket(f.score))).length,
    medium: findings.filter((f) => severityBucket(f.score) === 'medium').length,
    low: findings.filter((f) => severityBucket(f.score) === 'low').length,
    cves: findings
      .filter((f) => f.type === 'exposure')
      .reduce((n, f: any) => n + (f.data?.vulns?.length ?? 0), 0),
  }
}

// Freeze the current report (Markdown + HTML) as an immutable row. Returns null
// if the domain is gone.
export function createSnapshot(domainId: number, label?: string) {
  const domain = getDomain(domainId)
  if (!domain) return null
  const iso = new Date().toISOString()
  const contentMd = buildDomainReport(domainId, iso)
  const contentHtml = buildDomainReportHtml(domainId, iso)
  if (contentMd == null || contentHtml == null) return null
  const meta = summariseFindings(domainId)
  const res = db
    .insert(reportSnapshots)
    .values({
      domainId,
      host: domain.host,
      label: label?.trim() || null,
      contentMd,
      contentHtml,
      meta: JSON.stringify(meta),
    })
    .run()
  return metaRow(Number(res.lastInsertRowid))
}

// List metadata only (never the heavy content) for the snapshots panel.
export function listSnapshots(domainId: number) {
  return db
    .select({
      id: reportSnapshots.id,
      host: reportSnapshots.host,
      label: reportSnapshots.label,
      meta: reportSnapshots.meta,
      createdAt: reportSnapshots.createdAt,
    })
    .from(reportSnapshots)
    .where(eq(reportSnapshots.domainId, domainId))
    .orderBy(desc(reportSnapshots.id))
    .all()
    .map((r) => ({ ...r, meta: r.meta ? (JSON.parse(r.meta) as SnapshotMeta) : null }))
}

// Single-row metadata read (used right after insert).
function metaRow(id: number) {
  const r = db
    .select({
      id: reportSnapshots.id,
      host: reportSnapshots.host,
      label: reportSnapshots.label,
      meta: reportSnapshots.meta,
      createdAt: reportSnapshots.createdAt,
    })
    .from(reportSnapshots)
    .where(eq(reportSnapshots.id, id))
    .limit(1)
    .all()[0]
  return r ? { ...r, meta: r.meta ? (JSON.parse(r.meta) as SnapshotMeta) : null } : null
}

// Full row incl. frozen content (for download).
export function getSnapshot(id: number) {
  return db.select().from(reportSnapshots).where(eq(reportSnapshots.id, id)).limit(1).all()[0]
}

export function deleteSnapshot(id: number): boolean {
  return db.delete(reportSnapshots).where(eq(reportSnapshots.id, id)).run().changes > 0
}
