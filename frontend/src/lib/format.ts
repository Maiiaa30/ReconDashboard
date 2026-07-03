// Compact relative time, e.g. "just now", "5m ago", "3h ago", "2d ago".
export function timeAgo(ms: number | null | undefined): string {
  if (!ms) return 'never'
  const diff = Date.now() - ms
  if (diff < 0) return 'just now'
  const s = Math.floor(diff / 1000)
  if (s < 60) return 'just now'
  const m = Math.floor(s / 60)
  if (m < 60) return `${m}m ago`
  const h = Math.floor(m / 60)
  if (h < 24) return `${h}h ago`
  const d = Math.floor(h / 24)
  if (d < 30) return `${d}d ago`
  return new Date(ms).toLocaleDateString()
}

// One-line human summary of a finding, by type.
export function summarizeFinding(type: string, data: any): string {
  if (!data) return type
  switch (type) {
    case 'new_subdomain': {
      const host = String(data.host ?? '')
      const status = data.status != null ? `[${data.status}] ` : ''
      const title = data.title ? ` — ${String(data.title).slice(0, 60)}` : ''
      return `${status}${host}${title}`
    }
    case 'exposure': {
      const ports = Array.isArray(data.ports) ? data.ports.length : 0
      const cves = Array.isArray(data.vulns) ? data.vulns.length : 0
      return `${data.ip ?? '?'} · ${ports} port(s)${cves ? ` · ${cves} CVE(s)` : ''}`
    }
    case 'osint':
      return `OSINT for ${data.domain ?? '?'}`
    case 'nmap': {
      const open = Array.isArray(data.openPorts) ? data.openPorts.length : 0
      return `${data.target ?? '?'} · ${open} open port(s)`
    }
    case 'nuclei':
      return `${data.severity ?? 'info'}: ${data.name ?? data.templateId ?? '?'} @ ${data.target ?? ''}`
    case 'ffuf':
      return `${data.status ?? '?'} ${data.url ?? ''}`
    case 'cve_new':
      return `New CVE ${data.cveId ?? '?'}${data.kev ? ' [KEV]' : ''} on ${data.host ?? data.ip ?? '?'}${data.cvss != null ? ` · CVSS ${data.cvss}` : ''}`
    case 'tool':
      return `${data.tool ?? 'tool'}: ${data.title ?? data.detail ?? ''}${data.target ? ` @ ${data.target}` : ''}`
    case 'owasp':
      return `${data.category ? data.category + ' — ' : ''}${data.name ?? data.title ?? '?'}${data.url ? ` @ ${data.url}` : ''}`
    case 'origin': {
      const waf = data.provider ? `behind ${data.provider}` : 'no CDN/WAF'
      const found = (data.confirmedOrigins ?? []).length
      return `${data.domain ?? ''} — ${waf}${found ? `, origin: ${data.confirmedOrigins[0]?.ip}` : ''}`
    }
    default:
      // Never dump raw JSON into the UI — fall back to the most human field.
      return String(data.title ?? data.name ?? data.host ?? data.target ?? data.ip ?? data.url ?? type)
  }
}

// Compact one-line summary of a finished job's result, by job type.
export function summarizeJob(type: string, result: any): string {
  if (!result || typeof result !== 'object') return ''
  switch (type) {
    case 'subdomain_discovery':
      return `${result.discovered ?? 0} found, ${result.newCount ?? 0} new`
    case 'exposure_scan':
      return `${result.exposedIps ?? 0} exposed IP(s) of ${result.ipsResolved ?? 0} resolved`
    case 'osint_gather':
      return `OSINT for ${result.domain ?? ''}`
    case 'nmap_scan':
      return result.available === false ? 'nmap not installed' : `${(result.openPorts ?? []).length} open port(s)`
    case 'nuclei_scan':
      return result.available === false ? 'nuclei not installed' : `${result.count ?? 0} finding(s)`
    case 'ffuf_scan':
      return result.available === false ? 'ffuf not installed' : `${result.hits ?? 0} hit(s)`
    case 'screenshot':
      return result.available === false ? 'chromium not installed' : `${result.captured ?? 0} captured`
    case 'origin_scan':
      return `${result.behindCdn ? `behind ${result.provider}` : 'no CDN'}${result.confirmedOrigins ? `, ${result.confirmedOrigins} origin(s)` : ''}`
    default:
      return ''
  }
}

export type RiskLevel = 'none' | 'low' | 'medium' | 'high'

export function riskFromScore(score: number | null | undefined): RiskLevel {
  if (score == null) return 'none'
  if (score >= 70) return 'high'
  if (score >= 40) return 'medium'
  if (score >= 20) return 'low'
  return 'none'
}
