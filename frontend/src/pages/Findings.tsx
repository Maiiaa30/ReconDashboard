import { useCallback, useEffect, useState } from 'react'
import { api, type Finding } from '../api'
import { useApp } from '../state'
import { Badge, Empty, PageHeader, ScoreBadge } from '../components/ui'

const TYPE_OPTIONS = ['', 'new_subdomain', 'exposure', 'osint', 'nmap', 'nuclei', 'ffuf'] as const

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

  useEffect(load, [load])

  return (
    <div>
      <PageHeader title="Findings" subtitle="Scored, highest priority first" />

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
      </div>

      {findings.length === 0 ? (
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
              {findings.map((f) => (
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
                        <Badge key={t}>{t}</Badge>
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
