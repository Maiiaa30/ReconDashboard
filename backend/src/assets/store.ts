import { and, eq, notInArray } from 'drizzle-orm'
import { db } from '../db/index'
import { assetFindings, assets, findingLinks, type AssetRow } from '../db/schema'

// Durable asset inventory store. Upserts are keyed on (domain, kind, value) so a
// re-scan refreshes lastSeen and enriches (ip/asn/cdn) without duplicating; the
// finding link is the many-to-many edge for "which findings mention this asset".

export type AssetKind = 'host' | 'ip' | 'service'

export interface AssetInput {
  domainId: number
  kind: AssetKind
  value: string
  ip?: string | null
  port?: number | null
  asn?: string | null
  asnName?: string | null
  cdn?: string | null
}

// Insert or refresh an asset; returns its id. Non-null enrichment fields overwrite
// (a later scan that learns the ASN fills it in); undefined fields are left as-is.
export function upsertAsset(a: AssetInput): number {
  const now = new Date()
  const existing = db
    .select({ id: assets.id })
    .from(assets)
    .where(and(eq(assets.domainId, a.domainId), eq(assets.kind, a.kind), eq(assets.value, a.value)))
    .limit(1)
    .all()[0]
  if (existing) {
    db.update(assets)
      .set({
        lastSeen: now,
        ip: a.ip ?? undefined,
        port: a.port ?? undefined,
        asn: a.asn ?? undefined,
        asnName: a.asnName ?? undefined,
        cdn: a.cdn ?? undefined,
      })
      .where(eq(assets.id, existing.id))
      .run()
    return existing.id
  }
  const res = db
    .insert(assets)
    .values({ domainId: a.domainId, kind: a.kind, value: a.value, ip: a.ip ?? null, port: a.port ?? null, asn: a.asn ?? null, asnName: a.asnName ?? null, cdn: a.cdn ?? null, firstSeen: now, lastSeen: now })
    .run()
  return Number(res.lastInsertRowid)
}

// Link an asset to a finding (idempotent). No-op for a null finding id.
export function linkAssetFinding(assetId: number, findingId: number | null | undefined): void {
  if (findingId == null) return
  const related = db.select({ findingId: assetFindings.findingId }).from(assetFindings).where(eq(assetFindings.assetId, assetId)).limit(100).all()
  db.insert(assetFindings).values({ assetId, findingId }).onConflictDoNothing().run()
  for (const row of related) {
    if (row.findingId === findingId) continue
    const [fromId, toId] = row.findingId < findingId ? [row.findingId, findingId] : [findingId, row.findingId]
    db.insert(findingLinks).values({ fromId, toId, kind: 'same_asset' }).onConflictDoNothing().run()
  }
}

export function listAssets(domainId: number): AssetRow[] {
  return db.select().from(assets).where(eq(assets.domainId, domainId)).all()
}

// Keep the current service inventory honest while history remains available in
// findings/snapshots. Only reconcile an IP after its provider lookup succeeded.
export function reconcileServicesForIp(domainId: number, ip: string, ports: number[]): void {
  const values = [...new Set(ports)].map((port) => `${ip}:${port}`)
  const base = and(eq(assets.domainId, domainId), eq(assets.kind, 'service'), eq(assets.ip, ip))
  db.delete(assets)
    .where(values.length ? and(base, notInArray(assets.value, values)) : base)
    .run()
}

export function countAssets(domainId: number): number {
  return db.select({ id: assets.id }).from(assets).where(eq(assets.domainId, domainId)).all().length
}

export function countSameAssetLinks(): number {
  return db.select({ id: findingLinks.id }).from(findingLinks).where(eq(findingLinks.kind, 'same_asset')).all().length
}
