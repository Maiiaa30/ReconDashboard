import type { FastifyPluginAsync } from 'fastify'
import { and, desc, eq, gt, isNotNull, lt } from 'drizzle-orm'
import { db } from '../db/index'
import { domains, subdomains, users } from '../db/schema'
import { getOperatorById } from '../auth/seed'
import { domainOverviews } from '../domains/overview'
import { listFindings } from '../findings/store'

// How soon an authorization window has to expire to be flagged on the Today panel.
const EXPIRING_WITHIN_DAYS = 7
const DAY_MS = 24 * 60 * 60 * 1000
// Re-baseline the "last viewed" marker at most this often, so polling the Today
// panel doesn't reset its diff window every few seconds.
const VIEW_DEBOUNCE_MS = 10 * 60 * 1000

export const homeRoutes: FastifyPluginAsync = async (app) => {
  app.get('/api/home', async () => {
    const overview = domainOverviews()
    const topFindings = listFindings({ limit: 400 })
      .filter((f) => f.status === 'open' && (f.score ?? 0) >= 40)
      .slice(0, 15)
      .map((f) => ({ id: f.id, domainId: f.domainId, type: f.type, data: f.data, score: f.score, tags: f.tags }))
    // "What changed": newest new-CVE-on-a-known-asset alerts, most recent first.
    const recentChanges = listFindings({ type: 'cve_new', limit: 50 })
      .sort((a, b) => new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime())
      .slice(0, 8)
      .map((f) => ({ id: f.id, domainId: f.domainId, data: f.data, score: f.score, createdAt: f.createdAt }))
    return { overview, topFindings, recentChanges }
  })

  // "Today": a ranked "what changed / got riskier since you last looked" panel.
  // `since` = the operator's last Home visit (fallback: 7 days ago). Returning
  // this view also advances that timestamp, so the next visit diffs from now.
  app.get('/api/home/today', async (request) => {
    const userId = request.session.userId!
    const op = getOperatorById(userId)
    const now = new Date()
    const since = op?.lastDashboardViewedAt ?? new Date(now.getTime() - 7 * DAY_MS)
    const sinceMs = since.getTime()

    const hostById = new Map(db.select({ id: domains.id, host: domains.host }).from(domains).all().map((d) => [d.id, d.host]))
    const isNew = (ts: unknown) => !!ts && new Date(ts as string).getTime() > sinceMs

    const all = listFindings({ limit: 800 })

    // 1) New high-score open findings since the last visit.
    const findings = all
      .filter((f) => f.status === 'open' && f.type !== 'cve_new' && (f.score ?? 0) >= 60 && isNew(f.createdAt))
      .sort((a, b) => (b.score ?? 0) - (a.score ?? 0))
      .slice(0, 8)
      .map((f) => ({ id: f.id, domainId: f.domainId, host: f.domainId != null ? hostById.get(f.domainId) ?? null : null, type: f.type, data: f.data, score: f.score, createdAt: f.createdAt }))

    // 2) New CVEs on known assets (cve_new findings) since the last visit.
    const cves = all
      .filter((f) => f.type === 'cve_new' && isNew(f.createdAt))
      .sort((a, b) => (b.score ?? 0) - (a.score ?? 0))
      .slice(0, 8)
      .map((f) => ({ id: f.id, domainId: f.domainId, host: f.domainId != null ? hostById.get(f.domainId) ?? null : null, data: f.data, score: f.score, createdAt: f.createdAt }))

    // 3) New subdomains since the last visit — login pages first (highest value).
    const newSubs = db
      .select()
      .from(subdomains)
      .where(gt(subdomains.firstSeen, since))
      .orderBy(desc(subdomains.loginHint), desc(subdomains.firstSeen))
      .limit(12)
      .all()
      .map((s) => ({
        id: s.id,
        domainId: s.domainId,
        domainHost: hostById.get(s.domainId) ?? null,
        host: s.host,
        httpStatus: s.httpStatus,
        title: s.title,
        scheme: s.scheme,
        loginHint: s.loginHint,
        firstSeen: s.firstSeen,
      }))

    // 4) Authorization windows expiring within the next EXPIRING_WITHIN_DAYS.
    const soon = new Date(now.getTime() + EXPIRING_WITHIN_DAYS * DAY_MS)
    const expiring = db
      .select({ id: domains.id, host: domains.host, authorizedUntil: domains.authorizedUntil })
      .from(domains)
      .where(and(isNotNull(domains.authorizedUntil), gt(domains.authorizedUntil, now), lt(domains.authorizedUntil, soon)))
      .orderBy(domains.authorizedUntil)
      .all()
      .map((d) => ({
        id: d.id,
        host: d.host,
        authorizedUntil: d.authorizedUntil,
        daysLeft: d.authorizedUntil ? Math.max(0, Math.ceil((d.authorizedUntil.getTime() - now.getTime()) / DAY_MS)) : null,
      }))

    // Advance the "last viewed" marker so the next visit diffs from now — but
    // DEBOUNCED: the panel is polled every few seconds, and advancing on every GET
    // both hammered the DB and shrank the "since" window to the poll interval (so
    // the panel emptied instantly). Only re-baseline once the marker is stale, so
    // the window stays stable across a session's polling.
    if (op && now.getTime() - sinceMs >= VIEW_DEBOUNCE_MS) {
      db.update(users).set({ lastDashboardViewedAt: now, updatedAt: now }).where(eq(users.id, userId)).run()
    }

    return {
      since: since.toISOString(),
      counts: { findings: findings.length, cves: cves.length, subdomains: newSubs.length, expiring: expiring.length },
      findings,
      cves,
      subdomains: newSubs,
      expiring,
    }
  })
}
