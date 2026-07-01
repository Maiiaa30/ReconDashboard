import type { FastifyPluginAsync, FastifyReply } from 'fastify'
import { getDomain } from '../domains/store'
import { listSubdomains } from '../subdomains/store'
import { listFindings, type FindingType } from '../findings/store'
import { buildDomainReport, buildDomainReportHtml } from '../findings/report'
import { toCsv } from '../util/csv'

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
