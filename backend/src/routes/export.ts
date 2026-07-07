import type { FastifyPluginAsync, FastifyReply } from 'fastify'
import { getDomain } from '../domains/store'
import { listSubdomains } from '../subdomains/store'
import { listFindings, type FindingType } from '../findings/store'
import { buildDomainReport, buildDomainReportHtml } from '../findings/report'
import { createSnapshot, deleteSnapshot, getSnapshot, listSnapshots } from '../findings/snapshots'
import { toCsv } from '../util/csv'
import { config } from '../config'
import { llmComplete, llmEnabled } from '../util/llm'

type Format = 'csv' | 'json' | 'txt'

function parseFormat(raw: string | undefined): Format {
  return raw === 'json' || raw === 'txt' ? raw : 'csv'
}

function send(reply: FastifyReply, format: Format, filename: string, body: string) {
  const types: Record<Format, string> = {
    csv: 'text/csv; charset=utf-8',
    json: 'application/json; charset=utf-8',
    txt: 'text/plain; charset=utf-8',
  }
  reply
    .header('Content-Type', types[format])
    .header('Content-Disposition', `attachment; filename="${filename}.${format}"`)
  return reply.send(body)
}

// Build a short human summary string for a finding (for CSV).
function summarize(type: string, data: any): string {
  if (!data) return ''
  switch (type) {
    case 'new_subdomain':
      return `${data.status != null ? `[${data.status}] ` : ''}${data.host ?? ''}${data.title ? ` - ${data.title}` : ''}`
    case 'exposure':
      return `${data.ip ?? ''} ports:${(data.ports ?? []).join('|')} cves:${(data.vulns ?? []).length}`
    case 'nuclei':
      return `${data.severity ?? ''} ${data.name ?? data.templateId ?? ''} ${data.matched ?? ''}`
    case 'nmap':
      return `${data.target ?? ''} open:${(data.openPorts ?? []).length}`
    case 'ffuf':
      return `${data.status ?? ''} ${data.url ?? ''}`
    case 'osint':
      return `OSINT ${data.domain ?? ''}`
    default:
      return JSON.stringify(data).slice(0, 200)
  }
}

export const exportRoutes: FastifyPluginAsync = async (app) => {
  // Per-domain engagement report. ?format=md (default) → Markdown; ?format=html
  // → a self-contained single-file HTML the operator can print to PDF. Both carry
  // exec summary, scope/authorization, methodology, findings by severity, detail
  // (with "why this score" + evidence), live subdomains, tech, exposure.
  app.get<{ Params: { id: string }; Querystring: { format?: string } }>(
    '/api/domains/:id/report',
    async (request, reply) => {
      const id = Number(request.params.id)
      const domain = getDomain(id)
      if (!domain) return reply.code(404).send({ error: 'domain not found' })
      const iso = new Date().toISOString()
      if (request.query.format === 'html') {
        const html = buildDomainReportHtml(id, iso)
        if (html == null) return reply.code(404).send({ error: 'domain not found' })
        reply
          .header('Content-Type', 'text/html; charset=utf-8')
          .header('Content-Disposition', `attachment; filename="${domain.host}-report.html"`)
        return reply.send(html)
      }
      const md = buildDomainReport(id, iso)
      if (md == null) return reply.code(404).send({ error: 'domain not found' })
      reply
        .header('Content-Type', 'text/markdown; charset=utf-8')
        .header('Content-Disposition', `attachment; filename="${domain.host}-report.md"`)
      return reply.send(md)
    },
  )

  // --- Immutable report snapshots ------------------------------------------
  // Freeze the current report so a delivered deliverable never changes under a
  // later re-scan.
  app.post<{ Params: { id: string }; Body: { label?: string } }>(
    '/api/domains/:id/report/snapshot',
    async (request, reply) => {
      const id = Number(request.params.id)
      if (!getDomain(id)) return reply.code(404).send({ error: 'domain not found' })
      const snap = createSnapshot(id, request.body?.label)
      if (!snap) return reply.code(404).send({ error: 'domain not found' })
      return reply.code(201).send({ snapshot: snap })
    },
  )

  app.get<{ Params: { id: string } }>('/api/domains/:id/report/snapshots', async (request, reply) => {
    const id = Number(request.params.id)
    if (!getDomain(id)) return reply.code(404).send({ error: 'domain not found' })
    return { snapshots: listSnapshots(id) }
  })

  // Download a frozen snapshot's content (?format=html|md). Not domain-scoped in
  // the path — the snapshot carries its own host.
  app.get<{ Params: { sid: string }; Querystring: { format?: string } }>(
    '/api/report/snapshots/:sid',
    async (request, reply) => {
      const snap = getSnapshot(Number(request.params.sid))
      if (!snap) return reply.code(404).send({ error: 'snapshot not found' })
      const html = request.query.format === 'html'
      const date = new Date(snap.createdAt).toISOString().slice(0, 10)
      const filename = `${snap.host}-report-${date}.${html ? 'html' : 'md'}`
      reply
        .header('Content-Type', html ? 'text/html; charset=utf-8' : 'text/markdown; charset=utf-8')
        .header('Content-Disposition', `attachment; filename="${filename}"`)
      return reply.send(html ? snap.contentHtml : snap.contentMd)
    },
  )

  app.delete<{ Params: { sid: string } }>('/api/report/snapshots/:sid', async (request, reply) => {
    if (!deleteSnapshot(Number(request.params.sid))) return reply.code(404).send({ error: 'snapshot not found' })
    return { ok: true }
  })

  // Optional AI-DRAFTED executive narrative (grounded strictly in the finding
  // data; scores stay deterministic). Off unless LLM_BASE_URL/LLM_MODEL are set.
  // NOTE: this sends target hostnames + finding summaries to the configured LLM.
  app.post<{ Params: { id: string } }>('/api/domains/:id/report/narrative', async (request, reply) => {
    if (!llmEnabled()) return reply.code(503).send({ error: 'LLM not configured (set LLM_BASE_URL and LLM_MODEL)' })
    const id = Number(request.params.id)
    const domain = getDomain(id)
    if (!domain) return reply.code(404).send({ error: 'domain not found' })

    const findings = listFindings({ domainId: id, limit: 5000 }).filter(
      (f) => (f as any).status !== 'false_positive' && (f as any).status !== 'ignored',
    )
    const score = (f: (typeof findings)[number]) => f.score ?? 0
    const high = findings.filter((f) => score(f) >= 70)
    const medium = findings.filter((f) => score(f) >= 40 && score(f) < 70)
    const subs = listSubdomains(id)
    const live = subs.filter((s) => s.httpStatus != null)
    const exposures = findings.filter((f) => f.type === 'exposure')
    const cves = exposures.reduce((n, f: any) => n + (f.data?.vulns?.length ?? 0), 0)
    const topLines = [...high, ...medium].slice(0, 15).map((f) => `- [${f.score}] ${summarize(f.type, f.data)}`).join('\n')

    const facts =
      `Target: ${domain.host}\n` +
      `Subdomains: ${subs.length} (${live.length} live)\n` +
      `Findings: ${high.length} high, ${medium.length} medium\n` +
      `CVEs across exposed IPs: ${cves}\n` +
      `Top findings:\n${topLines || '(none above the noise floor)'}`

    const system =
      'You are a penetration-test report writer. Write a concise executive summary (120-180 words) of the ' +
      'engagement, grounded STRICTLY in the facts provided. Do NOT invent findings, hosts, CVEs, or numbers ' +
      'not present in the facts. Emphasise business risk and the most severe issues. Plain professional prose ' +
      '— no bullet lists, no markdown headers, no preamble.'

    const narrative = await llmComplete(system, facts)
    if (!narrative) return reply.code(502).send({ error: 'the LLM did not return a narrative (check the endpoint/model)' })
    return { narrative, model: config.llm.model, note: 'AI draft — verify against the findings table before use.' }
  })

  // Subdomains export: csv | txt (hosts only) | json (full rows).
  app.get<{ Params: { id: string }; Querystring: { format?: string } }>(
    '/api/domains/:id/subdomains/export',
    async (request, reply) => {
      const id = Number(request.params.id)
      const domain = getDomain(id)
      if (!domain) return reply.code(404).send({ error: 'domain not found' })
      const format = parseFormat(request.query.format)
      const subs = listSubdomains(id)
      const base = `${domain.host}-subdomains`

      if (format === 'txt') {
        return send(reply, 'txt', base, subs.map((s) => s.host).join('\n'))
      }
      if (format === 'json') {
        return send(reply, 'json', base, JSON.stringify(subs, null, 2))
      }
      const headers = ['host', 'ip', 'http_status', 'title', 'server', 'scheme', 'source', 'is_new', 'first_seen', 'last_seen']
      const rows = subs.map((s) => [
        s.host, s.ipAddress, s.httpStatus, s.title, s.server, s.scheme, s.source,
        s.isNew ? 'yes' : 'no',
        s.firstSeen ? new Date(s.firstSeen).toISOString() : '',
        s.lastSeen ? new Date(s.lastSeen).toISOString() : '',
      ])
      return send(reply, 'csv', base, toCsv(headers, rows))
    },
  )

  // Findings export: csv (essentials) | json (full).
  app.get<{ Querystring: { domainId?: string; type?: string; format?: string } }>(
    '/api/findings/export',
    async (request, reply) => {
      const format = parseFormat(request.query.format)
      const domainId = request.query.domainId ? Number(request.query.domainId) : undefined
      const type = request.query.type as FindingType | undefined
      const findings = listFindings({ domainId, type, limit: 5000 })
      const base = `findings${domainId ? `-${domainId}` : ''}`

      if (format === 'json') {
        return send(reply, 'json', base, JSON.stringify(findings, null, 2))
      }
      // Include the operator's triage (status/note) and first/last-seen — the
      // artifact a lead/client sees should carry the triage judgment, not drop it.
      const headers = ['id', 'type', 'score', 'status', 'summary', 'note', 'tags', 'domain_id', 'first_seen', 'last_seen']
      const rows = findings.map((f) => [
        f.id, f.type, f.score, (f as any).status ?? '', summarize(f.type, f.data), (f as any).note ?? '',
        (f.tags ?? []).join('|'), f.domainId,
        f.createdAt ? new Date(f.createdAt).toISOString() : '',
        (f as any).lastSeenAt ? new Date((f as any).lastSeenAt).toISOString() : '',
      ])
      return send(reply, 'csv', base, toCsv(headers, rows))
    },
  )
}
