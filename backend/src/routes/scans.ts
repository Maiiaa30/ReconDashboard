import type { FastifyPluginAsync } from 'fastify'
import { assertScanAllowed, assertDomainActive, assertHostInScope, ScanPolicyError } from '../domains/scanPolicy'
import { getDomain } from '../domains/store'
import { listSubdomains } from '../subdomains/store'
import { enqueueJob, hasPendingJob, type JobType } from '../jobs/queue'
import { actorName, writeAudit } from '../audit/store'
import { isValidIp } from '../util/validate'

// A passively-observed CVE (cve_new) can be re-verified sparingly: running the
// PoC template is loud and some CVE templates are intrusive RCE checks, so a long
// cooldown keeps a click-happy operator from hammering a target.
const CVE_VERIFY_COOLDOWN_MS = 6 * 60 * 60 * 1000
const CVE_ID_RE = /^CVE-\d{4}-\d{4,10}$/i

// ACTIVE / LOUD scans. All gating (mode/confirm, target-belongs, authorization
// window, engagement scope, pending guard, cooldown) lives in assertScanAllowed;
// every allowed enqueue is written to the append-only audit ledger.
export const scanRoutes: FastifyPluginAsync = async (app) => {
  function makeRoute(path: string, jobType: JobType, build: (body: any, target: string) => Record<string, unknown>) {
    app.post<{ Params: { id: string }; Body: Record<string, unknown> }>(
      path,
      async (request, reply) => {
        const id = Number(request.params.id)
        try {
          const { domain, target } = await assertScanAllowed({
            domainId: id,
            target: request.body?.target as string | undefined,
            confirm: request.body?.confirm === true,
            jobType,
          })
          const params = { domainId: id, target, ...build(request.body ?? {}, target) }
          const jobId = enqueueJob(jobType, params)
          writeAudit({
            actor: actorName(request.session.userId),
            action: `enqueue:${jobType}`,
            domainId: id,
            target,
            mode: domain.mode,
            jobId,
            detail: build(request.body ?? {}, target),
          })
          return reply.code(202).send({ jobId })
        } catch (err) {
          if (err instanceof ScanPolicyError) {
            if (err.retryAfterSec) reply.header('Retry-After', String(err.retryAfterSec))
            return reply.code(err.status).send({ error: err.message, code: err.code })
          }
          throw err
        }
      },
    )
  }

  makeRoute('/api/domains/:id/scan/nmap', 'nmap_scan', (body) => ({
    ports: typeof body.ports === 'string' ? body.ports : undefined,
    deep: body.deep === true,
  }))

  makeRoute('/api/domains/:id/scan/nuclei', 'nuclei_scan', (body) => {
    // Template tags: accept a comma string, hand the handler a validated array.
    const rawTags = body.tags
    const tags =
      typeof rawTags === 'string'
        ? rawTags.split(',').map((t) => t.trim().toLowerCase()).filter((t) => /^[a-z0-9-]+$/.test(t))
        : undefined
    return {
      scheme: body.scheme === 'http' ? 'http' : 'https',
      severity: typeof body.severity === 'string' ? body.severity : undefined,
      tags,
    }
  })

  makeRoute('/api/domains/:id/scan/ffuf', 'ffuf_scan', (body) => ({
    scheme: body.scheme === 'http' ? 'http' : 'https',
    path: typeof body.path === 'string' ? body.path : 'FUZZ',
    wordlist: typeof body.wordlist === 'string' ? body.wordlist : undefined,
  }))

  // CVE verification: run the matching nuclei template against `target` to
  // confirm a passively-observed cve_new finding. Gated like any loud scan, with
  // a long cooldown. `ip` (optional) lets the handler upgrade the exact cve_new
  // finding in place (keyed cvenew:${ip}:${cveId}); target must be a hostname the
  // gate accepts (an IP-only asset can't be verified until it has a scannable host).
  app.post<{ Params: { id: string }; Body: Record<string, unknown> }>(
    '/api/domains/:id/verify-cve',
    async (request, reply) => {
      const id = Number(request.params.id)
      const cveId = String(request.body?.cveId ?? '').toUpperCase()
      if (!CVE_ID_RE.test(cveId)) return reply.code(400).send({ error: 'invalid CVE id', code: 'invalid_cve' })
      const ip = typeof request.body?.ip === 'string' && isValidIp(request.body.ip) ? request.body.ip : undefined
      try {
        const { domain, target } = await assertScanAllowed({
          domainId: id,
          target: request.body?.target as string | undefined,
          confirm: request.body?.confirm === true,
          jobType: 'cve_verify',
          cooldownMs: CVE_VERIFY_COOLDOWN_MS,
        })
        const scheme = request.body?.scheme === 'http' ? 'http' : 'https'
        const kev = request.body?.kev === true
        const jobId = enqueueJob('cve_verify', { domainId: id, target, cveId, ip, kev, scheme })
        writeAudit({
          actor: actorName(request.session.userId),
          action: 'enqueue:cve_verify',
          domainId: id,
          target,
          mode: domain.mode,
          jobId,
          detail: { cveId, ip },
        })
        return reply.code(202).send({ jobId })
      } catch (err) {
        if (err instanceof ScanPolicyError) {
          if (err.retryAfterSec) reply.header('Retry-After', String(err.retryAfterSec))
          return reply.code(err.status).send({ error: err.message, code: err.code })
        }
        throw err
      }
    },
  )

  // Attack-surface nmap sweep: fan out one nmap job per LIVE host of the domain
  // (apex + discovered subdomains that resolved to an IP or answered HTTP),
  // deduped by resolved IP so a shared origin / CDN isn't scanned many times.
  // Domain rails are checked once; each host is still scope-checked individually
  // (out-of-scope hosts are skipped, never scanned). Fan-out bypasses the
  // single-scan pending/cooldown guard by design.
  const SWEEP_MAX_HOSTS = 50
  app.post<{ Params: { id: string }; Body: { deep?: boolean; confirm?: boolean } }>(
    '/api/domains/:id/scan/nmap-sweep',
    async (request, reply) => {
      const id = Number(request.params.id)
      const confirm = request.body?.confirm === true
      const deep = request.body?.deep === true
      try {
        const domain = getDomain(id)
        if (!domain) return reply.code(404).send({ error: 'domain not found', code: 'not_found' })
        assertDomainActive(domain, confirm)
        // Don't stack a second sweep on top of one that's still draining.
        if (hasPendingJob('nmap_scan', id)) {
          return reply.code(409).send({ error: 'nmap scans are already queued for this domain', code: 'already_pending' })
        }

        // Candidate live hosts: apex (always) + subdomains with an IP or HTTP hit,
        // deduped by resolved IP.
        const seenIp = new Set<string>()
        const hosts: string[] = []
        const consider = (host: string, ip: string | null) => {
          if (ip) {
            if (seenIp.has(ip)) return
            seenIp.add(ip)
          }
          if (!hosts.includes(host)) hosts.push(host)
        }
        consider(domain.host, null)
        for (const s of listSubdomains(id)) {
          if (s.ipAddress || s.httpStatus != null) consider(s.host, s.ipAddress ?? null)
        }
        const capped = hosts.length > SWEEP_MAX_HOSTS
        const chosen = hosts.slice(0, SWEEP_MAX_HOSTS)

        // Resolve scope for every host FIRST (this is the async part — DNS). Only
        // after all awaits do we enqueue, so the guard re-check + fan-out below is
        // one synchronous block the event loop can't interleave.
        const valid: string[] = []
        const skipped: { host: string; reason: string }[] = []
        for (const host of chosen) {
          try {
            valid.push(await assertHostInScope(domain, host))
          } catch (err) {
            skipped.push({ host, reason: err instanceof ScanPolicyError ? err.code : 'error' })
          }
        }

        // Re-check the guard immediately before enqueuing (no await in between) so
        // two concurrent sweep POSTs can't both pass and each fan out 50 jobs.
        if (hasPendingJob('nmap_scan', id)) {
          return reply.code(409).send({ error: 'nmap scans are already queued for this domain', code: 'already_pending' })
        }
        const jobs = valid.map((target) => {
          const jobId = enqueueJob('nmap_scan', { domainId: id, target, deep })
          writeAudit({
            actor: actorName(request.session.userId),
            action: 'enqueue:nmap_scan',
            domainId: id,
            target,
            mode: domain.mode,
            jobId,
            detail: { sweep: true, deep },
          })
          return { host: target, jobId }
        })
        return reply.code(202).send({ queued: jobs.length, jobs, skipped, capped, considered: hosts.length })
      } catch (err) {
        if (err instanceof ScanPolicyError) {
          if (err.retryAfterSec) reply.header('Retry-After', String(err.retryAfterSec))
          return reply.code(err.status).send({ error: err.message, code: err.code })
        }
        throw err
      }
    },
  )
}
