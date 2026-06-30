import { useCallback, useEffect, useState } from 'react'
import { api, type Finding } from '../api'
import { useApp } from '../state'
import { Badge, Empty, ExportLinks, PageHeader, ScoreBadge } from '../components/ui'

const TYPE_OPTIONS = ['', 'new_subdomain', 'exposure', 'osint', 'nmap', 'nuclei', 'ffuf'] as const

// Color-code the highest-signal tags so they stand out.
function tagTone(tag: string): 'zinc' | 'blue' | 'amber' | 'red' | 'green' {
  if (/^(kev|cvss:critical|sev:critical|takeover|takeover-candidate|db-exposed)/.test(tag)) return 'red'
  if (/^(cvss:high|sev:high|admin-port|admin-surface|has-cve|auth-gated|kw:)/.test(tag)) return 'amber'
  if (/^(tech:|svc:|owasp:|shodan:)/.test(tag)) return 'blue'
  if (tag === 'live' || tag === 'http-2xx') return 'green'
  return 'zinc'
}

function summarize(finding: Finding): string {
  const data = finding.data ?? {}
  switch (finding.type) {
    case 'new_subdomain':
      return String(data.host ?? '')
    case 'exposure': {
      const ports = (data.ports ?? []) as unknown[]
      const vulns = (data.vulns ?? []) as unknown[]
      return `${data.ip} ports:${ports.join(',')}${vulns.length ? ` vulns:${vulns.length}` : ''}`
    }
    case 'nuclei':
      return `${data.severity} ${data.name ?? data.templateId}`
    case 'nmap': {
      const openPorts = (data.openPorts ?? []) as unknown[]
      return `${data.target} open:${openPorts.length}`
    }
    case 'ffuf':
      return `${data.status} ${data.url}`
    case 'osint':
      return String(data.domain ?? '')
    default:
      return JSON.stringify(data).slice(0, 120)
  }
}

export function Findings() {
  const { domains } = useApp()
  const [domainId, setDomainId] = useState<number | ''>('')
  const [type, setType] = useState('')
  const [tagFilter, setTagFilter] = useState('')
  const [findings, setFindings] = useState<Finding[]>([])

  const load = useCallback(() => {
    api
      .findings({
        domainId: domainId === '' ? undefined : domainId,
        type: type || undefined,
        limit: 500,
      })
      .then((r) => setFindings(r.findings))
      .catch(() => {})
  }, [domainId, type])

  useEffect(() => {
    void load()
  }, [load])

  const tagQuery = tagFilter.trim().toLowerCase()
  const filtered = tagQuery
    ? findings.filter((f) => f.tags.some((t) => t.toLowerCase().includes(tagQuery)))
    : findings

  const exportBase =
    `/findings/export?` +
    [domainId !== '' ? `domainId=${domainId}` : '', type ? `type=${type}` : '']
      .filter(Boolean)
      .join('&')

  return (
    <div>
      <PageHeader
        title="Findings"
        subtitle="Scored, highest priority first"
        actions={<ExportLinks base={exportBase} formats={['csv', 'json']} />}
      />

      <div className="mb-4 flex flex-wrap items-end gap-3">
        <label className="text-sm">
          <span className="text-zinc-400">Domain</span>
          <select
            value={domainId}
            onChange={(e) => setDomainId(e.target.value === '' ? '' : Number(e.target.value))}
            className="mt-1 block rounded-lg border border-zinc-700 bg-zinc-950 px-3 py-1.5 text-sm outline-none focus:border-zinc-500"
          >
            <option value="">All domains</option>
            {domains.map((d) => (
              <option key={d.id} value={d.id}>
                {d.host}
              </option>
            ))}
          </select>
        </label>
        <label className="text-sm">
          <span className="text-zinc-400">Type</span>
          <select
            value={type}
            onChange={(e) => setType(e.target.value)}
            className="mt-1 block rounded-lg border border-zinc-700 bg-zinc-950 px-3 py-1.5 text-sm outline-none focus:border-zinc-500"
          >
            {TYPE_OPTIONS.map((t) => (
              <option key={t || 'all'} value={t}>
                {t === '' ? 'All' : t}
              </option>
            ))}
          </select>
        </label>
        <label className="text-sm">
          <span className="text-zinc-400">Filter by tag</span>
          <input
            value={tagFilter}
            onChange={(e) => setTagFilter(e.target.value)}
            placeholder="e.g. kev, admin-port, takeover, tech:nginx"
            className="mt-1 block w-64 rounded-lg border border-zinc-700 bg-zinc-950 px-3 py-1.5 text-sm outline-none focus:border-zinc-500"
          />
        </label>
        <span className="pb-1.5 text-xs text-zinc-600">{filtered.length} shown</span>
      </div>

      {filtered.length === 0 ? (
        <Empty>No findings match these filters.</Empty>
      ) : (
        <div className="overflow-hidden rounded-xl border border-zinc-800">
          <table className="w-full text-sm">
            <thead className="bg-zinc-900/60 text-left text-xs text-zinc-500">
              <tr>
                <th className="px-3 py-2">Score</th>
                <th className="px-3 py-2">Type</th>
                <th className="px-3 py-2">Summary</th>
                <th className="px-3 py-2">Tags</th>
                <th className="px-3 py-2">When</th>
              </tr>
            </thead>
            <tbody>
              {filtered.map((f) => (
                <tr key={f.id} className="border-t border-zinc-800/60 align-top">
                  <td className="px-3 py-2">
                    <ScoreBadge score={f.score} />
                  </td>
                  <td className="px-3 py-2">
                    <Badge tone="blue">{f.type}</Badge>
                  </td>
                  <td className="px-3 py-2 font-mono text-zinc-200">{summarize(f)}</td>
                  <td className="px-3 py-2">
                    <div className="flex flex-wrap gap-1">
                      {f.tags.map((t) => (
                        <button key={t} onClick={() => setTagFilter(t)} title="filter by this tag">
                          <Badge tone={tagTone(t)}>{t}</Badge>
                        </button>
                      ))}
                    </div>
                  </td>
                  <td className="px-3 py-2 text-zinc-500">{new Date(f.createdAt).toLocaleString()}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  )
}
