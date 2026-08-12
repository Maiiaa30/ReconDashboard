import type { FastifyPluginAsync } from 'fastify'
import { eq, inArray } from 'drizzle-orm'
import { db } from '../db/index'
import { assetFindings, assetSnapshots, assets, findings, subdomains } from '../db/schema'
import { getDomain } from '../domains/store'
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
}
