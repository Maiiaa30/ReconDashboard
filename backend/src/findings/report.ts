import { getDomain } from '../domains/store'
import { listSubdomains } from '../subdomains/store'
import { listFindings } from './store'

// Markdown engagement report for a single domain, built from stored recon data.
// Pure string assembly — safe to render and to diff.

function cell(s: unknown): string {
  // Neutralise table-breaking characters inside a Markdown table cell.
  return String(s ?? '')
    .replace(/\|/g, '\\|')
    .replace(/\r?\n/g, ' ')
    .trim()
}

function summarize(type: string, data: any): string {
  if (!data) return type
  switch (type) {
    case 'new_subdomain':
      return `${data.status != null ? `[${data.status}] ` : ''}${data.host ?? ''}${data.title ? ` — ${data.title}` : ''}`
    case 'exposure':
      return `${data.ip ?? ''} · ${(data.ports ?? []).length} port(s) · ${(data.vulns ?? []).length} CVE(s)`
    case 'nuclei':
      return `${data.severity ?? 'info'}: ${data.name ?? data.templateId ?? ''} @ ${data.matched ?? data.target ?? ''}`
    case 'nmap':
      return `${data.target ?? ''} · ${(data.openPorts ?? []).length} open port(s)`
    case 'ffuf':
      return `${data.status ?? ''} ${data.url ?? ''}`
    case 'origin':
      return `${data.domain ?? ''} — ${data.provider ? `behind ${data.provider}` : 'no CDN'}`
    case 'osint':
      return `OSINT for ${data.domain ?? ''}`
    default:
      return JSON.stringify(data).slice(0, 120)
  }
}

const STATUS_LABEL: Record<string, string> = {
  open: 'open',
  confirmed: 'confirmed',
  false_positive: 'false positive',
  resolved: 'resolved',
  ignored: 'ignored',
}

type Row = ReturnType<typeof listFindings>[number]

function severityTable(rows: Row[]): string {
  if (rows.length === 0) return '_None._\n'
  const head = '| Score | Type | Summary | Status | Tags |\n|--:|---|---|---|---|\n'
  const body = rows
    .map(
      (f) =>
        `| ${f.score ?? '—'} | ${cell(f.type)} | ${cell(summarize(f.type, f.data))} | ${cell(STATUS_LABEL[(f as any).status] ?? (f as any).status)} | ${cell((f.tags ?? []).join(', '))} |`,
    )
    .join('\n')
  return head + body + '\n'
}

export function buildDomainReport(id: number, generatedAtIso: string): string | null {
  const domain = getDomain(id)
  if (!domain) return null

  const findings = listFindings({ domainId: id, limit: 5000 })
  const subs = listSubdomains(id)
  const live = subs.filter((s) => s.httpStatus != null)

  // Exclude noise (false positives / ignored) from the body, but report the count.
  const noise = findings.filter((f) => (f as any).status === 'false_positive' || (f as any).status === 'ignored')
  const reportable = findings.filter((f) => !noise.includes(f))
  const score = (f: Row) => f.score ?? 0
  const high = reportable.filter((f) => score(f) >= 70)
  const medium = reportable.filter((f) => score(f) >= 40 && score(f) < 70)
  const low = reportable.filter((f) => score(f) < 40)

  const byStatus = (s: string) => findings.filter((f) => (f as any).status === s).length
  const confirmed = reportable.filter((f) => (f as any).status === 'confirmed')

  // Exposure rollup from exposure findings.
  const exposures = findings.filter((f) => f.type === 'exposure')
  const ips = new Set(exposures.map((f: any) => f.data?.ip).filter(Boolean))
  const ports = exposures.reduce((n, f: any) => n + (f.data?.ports?.length ?? 0), 0)
  const cves = exposures.reduce((n, f: any) => n + (f.data?.vulns?.length ?? 0), 0)

  // Tech from the latest OSINT finding (if gathered).
  const osint = findings.find((f) => f.type === 'osint') as any
  const tech = osint?.data?.tech && !('error' in osint.data.tech) ? osint.data.tech : null

  const lines: string[] = []
  lines.push(`# Recon report — ${domain.host}`, '')
  lines.push('| | |', '|---|---|')
  lines.push(`| Domain | \`${domain.host}\` |`)
  lines.push(`| Label | ${domain.label ? cell(domain.label) : '—'} |`)
  lines.push(`| Mode | ${domain.mode} |`)
  lines.push(`| Generated | ${generatedAtIso} |`, '')

  lines.push('## Summary', '')
  lines.push(`- **Subdomains:** ${subs.length} (${live.length} live)`)
  lines.push(
    `- **Findings:** ${reportable.length} reportable — ${high.length} high · ${medium.length} medium · ${low.length} low${noise.length ? ` (${noise.length} false-positive/ignored excluded)` : ''}`,
  )
  lines.push(`- **Triage:** ${byStatus('open')} open · ${byStatus('confirmed')} confirmed · ${byStatus('resolved')} resolved`)
  lines.push(`- **Exposure:** ${ips.size} exposed IP(s) · ${ports} open port(s) · ${cves} CVE(s)`, '')

  if (tech) {
    lines.push('## Server & technologies', '')
    if (tech.os) lines.push(`- **OS:** ${cell(tech.os)}`)
    if (tech.server) lines.push(`- **Server:** ${cell(tech.server)}`)
    if (tech.cdn) lines.push(`- **CDN:** ${cell(tech.cdn)}`)
    if (tech.technologies?.length) lines.push(`- **Stack:** ${cell(tech.technologies.join(', '))}`)
    lines.push('')
  }

  lines.push('## Findings', '')
  lines.push(`### High (${high.length})`, '', severityTable(high), '')
  lines.push(`### Medium (${medium.length})`, '', severityTable(medium), '')
  lines.push(`### Low / info (${low.length})`, '', severityTable(low), '')

  if (confirmed.length) {
    lines.push(`## Confirmed findings (${confirmed.length})`, '')
    for (const f of confirmed) {
      lines.push(`- **${cell(summarize(f.type, f.data))}** (score ${f.score ?? '—'})`)
      if ((f as any).note) lines.push(`  - ${cell((f as any).note)}`)
    }
    lines.push('')
  }

  lines.push(`## Live subdomains (${live.length})`, '')
  if (live.length) {
    lines.push('| Host | HTTP | Title | Server | IP |', '|---|--:|---|---|---|')
    for (const s of live) {
      lines.push(`| ${cell(s.host)} | ${s.httpStatus ?? ''} | ${cell(s.title)} | ${cell(s.server)} | ${cell(s.ipAddress)} |`)
    }
  } else {
    lines.push('_None probed live._')
  }
  lines.push('')

  if (exposures.length) {
    lines.push('## Exposure', '', '| IP | Ports | CVEs |', '|---|---|---|')
    for (const f of exposures as any[]) {
      lines.push(`| ${cell(f.data?.ip)} | ${cell((f.data?.ports ?? []).join(', '))} | ${cell((f.data?.vulns ?? []).join(', '))} |`)
    }
    lines.push('')
  }

  lines.push('---', `_Generated by Recon Dashboard for authorized testing of ${domain.host}._`)
  return lines.join('\n')
}
