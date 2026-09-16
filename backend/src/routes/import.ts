import type { FastifyPluginAsync } from 'fastify'
import { getDomain } from '../domains/store'
import { importScanData, type ImportFormat } from '../findings/import'
import { actorName, writeAudit } from '../audit/store'

const FORMATS: ReadonlySet<string> = new Set(['nuclei', 'nmap', 'findings'])

// Import externally-produced scan output (Nuclei JSONL, Nmap XML, or a generic
// findings JSON bundle) into a domain's findings. This is passive ingest of data
// the operator already holds — not an active scan — so it is not scan-gated; it
// only requires the domain to exist. The body carries the raw file text
// (bodyLimit is 16MB, enough for typical scan outputs).
export const importRoutes: FastifyPluginAsync = async (app) => {
  app.post<{ Params: { id: string }; Body: { format?: string; content?: string } }>(
    '/api/domains/:id/import',
    async (request, reply) => {
      const id = Number(request.params.id)
      const domain = getDomain(id)
      if (!domain) return reply.code(404).send({ error: 'domain not found' })

      const format = String(request.body?.format ?? '')
      if (!FORMATS.has(format)) {
        return reply.code(400).send({ error: `unknown format — one of: ${[...FORMATS].join(', ')}` })
      }
      const content = request.body?.content
      if (typeof content !== 'string' || !content.trim()) {
        return reply.code(400).send({ error: 'content (the raw scan output) is required' })
      }

      const result = await importScanData(id, format as ImportFormat, content)
      writeAudit({
        actor: actorName(request.session.userId),
        action: 'import:scan',
        domainId: id,
        target: domain.host,
        mode: domain.mode,
        detail: { format, parsed: result.parsed, imported: result.imported, skipped: result.skipped },
      })
      return reply.code(200).send(result)
    },
  )
}
