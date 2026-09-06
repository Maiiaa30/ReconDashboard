import type { FastifyPluginAsync } from 'fastify'
import { and, eq, inArray, ne } from 'drizzle-orm'
import { db } from '../db/index'
import { assetFindings, assetSnapshots, assets, findings, subdomains } from '../db/schema'
import { getDomain } from '../domains/store'
import { queryFindings } from '../findings/store'
import { queryCaptures } from '../capture/store'
import { safeJsonParse } from '../util/json'

export const assetRoutes: FastifyPluginAsync = async (app) => {
  app.get<{ Params: { id: string } }>('/api/domains/:id/assets', async (request, reply) => {
    const domainId = Number(request.params.id)
    if (!getDomain(domainId)) return reply.code(404).send({ error: 'domain not found' })

    const rows = db.select().from(assets).where(eq(assets.domainId, domainId)).all()
    const ids = rows.map((row) => row.id)
    const links = ids.length
      ? db
          .select({ assetId: assetFindings.assetId, findingId: findings.id, score: findings.score, status: findings.status })
          .from(assetFindings)
          .innerJoin(findings, eq(assetFindings.findingId, findings.id))
          .where(inArray(assetFindings.assetId, ids))
          .all()
      : []
    const hostRows = db.select().from(subdomains).where(eq(subdomains.domainId, domainId)).all()
    const snapshots = db.select().from(assetSnapshots).where(eq(assetSnapshots.domainId, domainId)).all()

    const linksByAsset = new Map<number, typeof links>()
    for (const link of links) {
      const current = linksByAsset.get(link.assetId) ?? []
      current.push(link)
      linksByAsset.set(link.assetId, current)
    }
    const hostByName = new Map(hostRows.map((host) => [host.host, host]))
    const snapshotByIp = new Map(snapshots.map((snapshot) => [snapshot.ip, snapshot]))

    return {
      assets: rows.map((asset) => {
        const related = linksByAsset.get(asset.id) ?? []
        const host = asset.kind === 'host' ? hostByName.get(asset.value) : undefined
        const snapshot = asset.kind === 'host'
          ? snapshotByIp.get(`host:${asset.value}`) ?? (asset.ip ? snapshotByIp.get(asset.ip) : undefined)
          : asset.ip ? snapshotByIp.get(asset.ip) : asset.kind === 'ip' ? snapshotByIp.get(asset.value) : undefined
        return {
          ...asset,
          findingCount: related.length,
          activeFindingCount: related.filter((link) => !['false_positive', 'resolved', 'retest_passed', 'ignored'].includes(link.status)).length,
          maxScore: related.reduce<number | null>((max, link) => (link.score == null ? max : Math.max(max ?? 0, link.score)), null),
          findingIds: related.slice(0, 50).map((link) => link.findingId),
          httpStatus: host?.httpStatus ?? null,
          title: host?.title ?? snapshot?.title ?? null,
          server: host?.server ?? null,
          scheme: host?.scheme ?? null,
          ports: snapshot ? safeJsonParse<number[]>(snapshot.ports, []) : [],
          technologies: snapshot ? safeJsonParse<string[]>(snapshot.tech, []) : [],
          up: snapshot?.up ?? null,
          redirect: snapshot?.redirect ?? null,
          contentLength: snapshot?.contentLength ?? null,
          responseFingerprint: snapshot?.contentHash ?? null,
          screenshotFingerprint: snapshot?.screenshotHash ?? null,
        }
      }),
    }
  })

  // Per-asset investigation detail: everything known about one host/IP in one
  // place — its subdomain enrichment, the findings that mention it, recent
  // captured traffic, and other hosts it shares an IP / TLS cert / favicon with.
  app.get<{ Params: { id: string; assetId: string } }>('/api/domains/:id/assets/:assetId', async (request, reply) => {
    const domainId = Number(request.params.id)
    if (!getDomain(domainId)) return reply.code(404).send({ error: 'domain not found' })
    const assetId = Number(request.params.assetId)
    const asset = db
      .select()
      .from(assets)
      .where(and(eq(assets.id, assetId), eq(assets.domainId, domainId)))
      .get()
    if (!asset) return reply.code(404).send({ error: 'asset not found' })

    const host = asset.kind === 'host' ? asset.value : null
    const sub = host
      ? db.select().from(subdomains).where(and(eq(subdomains.domainId, domainId), eq(subdomains.host, host))).get() ?? null
      : null
    const ip = asset.ip ?? (asset.kind === 'ip' ? asset.value : null) ?? sub?.ipAddress ?? null

    // Findings and captures that mention this asset (reuses the server-side
    // filters so the shapes match the rest of the UI). status:'all' so triaged
    // findings still show in the investigation view.
    const findingsForAsset = queryFindings({ domainId, asset: asset.value, status: 'all', limit: 200 }).findings
    const captures = host ? queryCaptures({ domainId, q: host, limit: 25 }).captures : []

    // Hosts sharing a correlation signal with this one (excluding itself).
    const hostsWhere = (extra: ReturnType<typeof eq>) =>
      db
        .select({ host: subdomains.host })
        .from(subdomains)
        .where(host ? and(eq(subdomains.domainId, domainId), extra, ne(subdomains.host, host)) : and(eq(subdomains.domainId, domainId), extra))
        .all()
        .map((r) => r.host)
    const sameIp = ip ? hostsWhere(eq(subdomains.ipAddress, ip)) : []
    const sameCert = sub?.certFp ? hostsWhere(eq(subdomains.certFp, sub.certFp)) : []
    const sameFavicon = sub?.faviconHash != null ? hostsWhere(eq(subdomains.faviconHash, sub.faviconHash)) : []

    return { asset, subdomain: sub, findings: findingsForAsset, captures, related: { sameIp, sameCert, sameFavicon } }
  })
}
