import type { Domain } from '../db/schema'
import { getDomain } from '../domains/store'
import { listSubdomains } from '../subdomains/store'
import { safeJsonParse } from '../util/json'
import { parseScopeConfig } from '../util/scope'
import { listFindings } from './store'

// Engagement report for a single domain, built from stored recon data. A shared
// model (gather) feeds both the Markdown and the self-contained HTML builders, so
// the two never drift. Pure string assembly — safe to render and to diff.

function cell(s: unknown): string {
  // Neutralise table-breaking characters inside a Markdown table cell.
  return String(s ?? '')
    .replace(/\|/g, '\\|')
    .replace(/\r?\n/g, ' ')
    .trim()
}

function esc(s: unknown): string {
  return String(s ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
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
    case 'owasp':
      return `${data.category ? data.category + ' — ' : ''}${data.name ?? ''}${data.url ? ` @ ${data.url}` : ''}`
    case 'tool':
      return `${data.tool ?? 'tool'}: ${data.title ?? ''}`
    case 'origin':
      return `${data.domain ?? ''} — ${data.provider ? `behind ${data.provider}` : 'no CDN'}${(data.confirmedOrigins ?? []).length ? `, origin ${data.confirmedOrigins[0]?.ip}` : ''}`
    case 'osint':
      return `OSINT for ${data.domain ?? ''}`
    case 'cve_new':
      return `New CVE ${data.cveId ?? ''}${data.kev ? ' [KEV]' : ''} on ${data.host ?? data.ip ?? ''}${data.cvss != null ? ` (CVSS ${data.cvss})` : ''}`
    default:
      // Never dump raw JSON into a client deliverable.
      return String(data.title ?? data.name ?? data.host ?? data.target ?? type)
  }
}

const STATUS_LABEL: Record<string, string> = {
  open: 'open',
  confirmed: 'confirmed',
  false_positive: 'false positive',
  resolved: 'resolved',
  ignored: 'ignored',
}

// Which technique each finding type represents, for the Methodology section.
const TYPE_METHOD: Record<string, string> = {
  new_subdomain: 'Subdomain discovery (crt.sh / certspotter / subfinder) + HTTP probing',
  exposure: 'Exposure & CVE enrichment (Shodan InternetDB + cvedb)',
  osint: 'Passive OSINT (DNS, WHOIS, CT logs, tech fingerprint, archived URLs)',
  origin: 'Origin / WAF discovery',
  nmap: 'Port & service scan (nmap)',
  nuclei: 'Template scan (nuclei)',
  ffuf: 'Content discovery (ffuf)',
  owasp: 'Active OWASP checks (headers, sensitive files, reflected XSS, open redirect, CORS, TRACE, listing)',
  tool: 'Active tooling (katana / naabu / dalfox / sslscan / wpenum)',
}

type Row = ReturnType<typeof listFindings>[number]

interface ReportModel {
  domain: Domain
  generatedAtIso: string
  subsTotal: number
  live: ReturnType<typeof listSubdomains>
  reportable: Row[]
  noiseCount: number
  high: Row[]
  medium: Row[]
  low: Row[]
  confirmed: Row[]
  counts: { open: number; confirmed: number; resolved: number }
  exposure: { ips: number; ports: number; cves: number; rows: Row[] }
  tech: any | null
  methods: string[]
}

function gather(id: number): ReportModel | null {
  const domain = getDomain(id)
  if (!domain) return null

  const findings = listFindings({ domainId: id, limit: 5000 })
  const subs = listSubdomains(id)
  const live = subs.filter((s) => s.httpStatus != null)

  // Set (not array + .includes) so the reportable filter is O(n), not O(n²) on a
  // large finding set.
  const noise = new Set(
    findings.filter((f) => (f as any).status === 'false_positive' || (f as any).status === 'ignored'),
  )
  const reportable = findings.filter((f) => !noise.has(f))
  const score = (f: Row) => f.score ?? 0
  const high = reportable.filter((f) => score(f) >= 70)
  const medium = reportable.filter((f) => score(f) >= 40 && score(f) < 70)
  const low = reportable.filter((f) => score(f) < 40)
  const byStatus = (s: string) => findings.filter((f) => (f as any).status === s).length
  const confirmed = reportable.filter((f) => (f as any).status === 'confirmed')

  const exposures = findings.filter((f) => f.type === 'exposure')
  const ips = new Set(exposures.map((f: any) => f.data?.ip).filter(Boolean))
  const ports = exposures.reduce((n, f: any) => n + (f.data?.ports?.length ?? 0), 0)
  const cves = exposures.reduce((n, f: any) => n + (f.data?.vulns?.length ?? 0), 0)

  const osint = findings.find((f) => f.type === 'osint') as any
  const tech = osint?.data?.tech && !('error' in osint.data.tech) ? osint.data.tech : null

  const typesPresent = new Set(findings.map((f) => f.type))
  const methods = [...typesPresent].map((t) => TYPE_METHOD[t]).filter(Boolean) as string[]

  return {
    domain,
    generatedAtIso: '',
    subsTotal: subs.length,
    live,
    reportable,
    noiseCount: noise.size,
    high,
    medium,
    low,
    confirmed,
    counts: { open: byStatus('open'), confirmed: byStatus('confirmed'), resolved: byStatus('resolved') },
    exposure: { ips: ips.size, ports, cves, rows: exposures },
    tech,
    methods,
  }
}

// Deterministic one-paragraph executive summary from the model.
function execSummary(m: ReportModel): string {
  const top = m.confirmed[0] ?? m.high[0] ?? m.medium[0]
  const topStr = top ? ` The most notable is "${summarize(top.type, (top as any).data)}" (score ${top.score ?? '—'}).` : ''
  const risk = m.high.length ? 'elevated' : m.medium.length ? 'moderate' : 'low'
  return (
    `Assessment of ${m.domain.host} surfaced ${m.reportable.length} reportable finding(s) — ` +
    `${m.high.length} high, ${m.medium.length} medium, ${m.low.length} low — across ${m.live.length} live ` +
    `subdomain(s) of ${m.subsTotal} discovered. Exposure enrichment found ${m.exposure.cves} CVE(s) over ` +
    `${m.exposure.ips} exposed IP(s). Overall risk signal is ${risk}.${topStr}`
  )
}

function scopeSummary(domain: Domain): { allow: string[]; deny: string[] } {
  return parseScopeConfig(safeJsonParse<unknown>(domain.scopeConfig, {}))
}

function windowStr(domain: Domain): string {
  const f = domain.authorizedFrom ? new Date(domain.authorizedFrom).toISOString() : null
  const u = domain.authorizedUntil ? new Date(domain.authorizedUntil).toISOString() : null
  if (!f && !u) return 'no explicit window'
  return `${f ?? 'unbounded'} → ${u ?? 'unbounded'}`
}

function scoreReasonsOf(f: Row): string[] {
  const r = (f as any).data?._scoreReasons
  return Array.isArray(r) ? r.map(String) : []
}

// --- Markdown ---------------------------------------------------------------

function severityTable(rows: Row[]): string {
  if (rows.length === 0) return '_None._\n'
  const head = '| Score | Type | Summary | Status | Tags |\n|--:|---|---|---|---|\n'
  const body = rows
    .map(
      (f) =>
        `| ${f.score ?? '—'} | ${cell(f.type)} | ${cell(summarize(f.type, (f as any).data))} | ${cell(STATUS_LABEL[(f as any).status] ?? (f as any).status)} | ${cell((f.tags ?? []).join(', '))} |`,
    )
    .join('\n')
  return head + body + '\n'
}

export function buildDomainReport(id: number, generatedAtIso: string): string | null {
  const m = gather(id)
  if (!m) return null
  m.generatedAtIso = generatedAtIso
  const { domain } = m
  const scope = scopeSummary(domain)

  const lines: string[] = []
  lines.push(`# Recon report — ${domain.host}`, '')

  lines.push('## Executive summary', '', execSummary(m), '')

  lines.push('## Scope & authorization', '')
  lines.push('| | |', '|---|---|')
  lines.push(`| Target | \`${domain.host}\` |`)
  lines.push(`| Label | ${domain.label ? cell(domain.label) : '—'} |`)
  lines.push(`| Mode | ${domain.mode} |`)
  lines.push(`| Scope allow | ${scope.allow.length ? cell(scope.allow.join(', ')) : 'anything within the domain'} |`)
  lines.push(`| Scope deny | ${scope.deny.length ? cell(scope.deny.join(', ')) : '—'} |`)
  lines.push(`| Authorization window | ${windowStr(domain)} |`)
  lines.push(`| Generated | ${generatedAtIso} |`, '')
  lines.push('> Testing was performed under authorization for the target above. Active scans are gated by mode, scope, and the authorization window.', '')

  if (m.methods.length) {
    lines.push('## Methodology', '')
    for (const meth of m.methods) lines.push(`- ${meth}`)
    lines.push('')
  }

  lines.push('## Summary', '')
  lines.push(`- **Subdomains:** ${m.subsTotal} (${m.live.length} live)`)
  lines.push(
    `- **Findings:** ${m.reportable.length} reportable — ${m.high.length} high · ${m.medium.length} medium · ${m.low.length} low${m.noiseCount ? ` (${m.noiseCount} false-positive/ignored excluded)` : ''}`,
  )
  lines.push(`- **Triage:** ${m.counts.open} open · ${m.counts.confirmed} confirmed · ${m.counts.resolved} resolved`)
  lines.push(`- **Exposure:** ${m.exposure.ips} exposed IP(s) · ${m.exposure.ports} open port(s) · ${m.exposure.cves} CVE(s)`, '')
  lines.push('_Severity by score: **high** ≥ 70 · **medium** 40–69 · **low/info** < 40._', '')

  if (m.tech) {
    lines.push('## Server & technologies', '')
    if (m.tech.os) lines.push(`- **OS:** ${cell(m.tech.os)}`)
    if (m.tech.server) lines.push(`- **Server:** ${cell(m.tech.server)}`)
    if (m.tech.cdn) lines.push(`- **CDN:** ${cell(m.tech.cdn)}`)
    if (m.tech.technologies?.length) lines.push(`- **Stack:** ${cell(m.tech.technologies.join(', '))}`)
    lines.push('')
  }

  lines.push('## Findings', '')
  lines.push(`### High (${m.high.length})`, '', severityTable(m.high), '')
  lines.push(`### Medium (${m.medium.length})`, '', severityTable(m.medium), '')
  lines.push(`### Low / info (${m.low.length})`, '', severityTable(m.low), '')

  // Detail for the findings that matter: confirmed first, then any remaining high.
  const detailed = [...m.confirmed, ...m.high.filter((f) => !m.confirmed.includes(f))]
  if (detailed.length) {
    lines.push(`## Finding detail (${detailed.length})`, '')
    for (const f of detailed) {
      lines.push(`### ${cell(summarize(f.type, (f as any).data))} — score ${f.score ?? '—'} (${STATUS_LABEL[(f as any).status] ?? 'open'})`, '')
      const reasons = scoreReasonsOf(f)
      if (reasons.length) {
        lines.push('**Why this score:**')
        for (const r of reasons) lines.push(`- ${cell(r)}`)
        lines.push('')
      }
      if ((f as any).note) lines.push(`**Analyst note:** ${cell((f as any).note)}`, '')
      const ev = collectEvidence(f)
      if (ev.length) {
        lines.push('**Evidence:**', '', '```', evidenceText(ev), '```', '')
      }
    }
  }

  lines.push(`## Live subdomains (${m.live.length})`, '')
  if (m.live.length) {
    lines.push('| Host | HTTP | Title | Server | IP |', '|---|--:|---|---|---|')
    for (const s of m.live) {
      lines.push(`| ${cell(s.host)} | ${s.httpStatus ?? ''} | ${cell(s.title)} | ${cell(s.server)} | ${cell(s.ipAddress)} |`)
    }
  } else {
    lines.push('_None probed live._')
  }
  lines.push('')

  if (m.exposure.rows.length) {
    lines.push('## Exposure', '', '| IP | Ports | CVEs |', '|---|---|---|')
    for (const f of m.exposure.rows as any[]) {
      lines.push(`| ${cell(f.data?.ip)} | ${cell((f.data?.ports ?? []).join(', '))} | ${cell((f.data?.vulns ?? []).join(', '))} |`)
    }
    lines.push('')
  }

  lines.push('---', `_Generated by Recon Dashboard for authorized testing of ${domain.host}._`)
  return lines.join('\n')
}

// All evidence for a finding: any auto-captured repro plus operator-attached
// items (data.evidence array). Tolerates a legacy single-object data.evidence.
function collectEvidence(f: any): any[] {
  const out: any[] = []
  if (f?.data?.repro) out.push(f.data.repro)
  const att = f?.data?.evidence
  if (Array.isArray(att)) out.push(...att)
  else if (att && !f?.data?.repro) out.push(att)
  return out
}

// Render an evidence object (or array of them) as compact plain text.
function evidenceText(ev: any): string {
  if (typeof ev === 'string') return ev.slice(0, 2000)
  if (Array.isArray(ev)) return ev.map(evidenceText).join('\n\n— — —\n\n').slice(0, 12_000)
  const parts: string[] = []
  if (ev.request) parts.push(`> ${ev.request}`)
  if (ev.payload) parts.push(`payload: ${ev.payload}`)
  if (ev.responseStatus != null) parts.push(`< HTTP ${ev.responseStatus}`)
  if (ev.headersSnippet) parts.push(String(ev.headersSnippet))
  if (ev.response) parts.push(String(ev.response).slice(0, 2000))
  if (ev.bodyExcerpt) parts.push(String(ev.bodyExcerpt).slice(0, 800))
  if (ev.screenshotPath) parts.push(`[screenshot: ${ev.screenshotPath}]`)
  if (ev.note) parts.push(`note: ${ev.note}`)
  return parts.join('\n').slice(0, 3000) || JSON.stringify(ev).slice(0, 800)
}

// --- HTML (self-contained, printable to PDF) --------------------------------

function htmlTable(rows: Row[]): string {
  if (!rows.length) return '<p class="muted">None.</p>'
  const body = rows
    .map(
      (f) =>
        `<tr><td class="num">${f.score ?? '—'}</td><td>${esc(f.type)}</td><td>${esc(summarize(f.type, (f as any).data))}</td><td>${esc(STATUS_LABEL[(f as any).status] ?? (f as any).status)}</td><td class="tags">${esc((f.tags ?? []).join(', '))}</td></tr>`,
    )
    .join('')
  return `<table><thead><tr><th>Score</th><th>Type</th><th>Summary</th><th>Status</th><th>Tags</th></tr></thead><tbody>${body}</tbody></table>`
}

export function buildDomainReportHtml(id: number, generatedAtIso: string): string | null {
  const m = gather(id)
  if (!m) return null
  m.generatedAtIso = generatedAtIso
  const { domain } = m
  const scope = scopeSummary(domain)
  const sev = (f: Row) => ((f.score ?? 0) >= 70 ? 'high' : (f.score ?? 0) >= 40 ? 'medium' : 'low')

  const detailed = [...m.confirmed, ...m.high.filter((f) => !m.confirmed.includes(f))]
  const detailHtml = detailed
    .map((f) => {
      const reasons = scoreReasonsOf(f)
      const reasonsHtml = reasons.length ? `<div class="why"><strong>Why this score</strong><ul>${reasons.map((r) => `<li>${esc(r)}</li>`).join('')}</ul></div>` : ''
      const note = (f as any).note ? `<p><strong>Analyst note:</strong> ${esc((f as any).note)}</p>` : ''
      const ev = collectEvidence(f)
      const evHtml = ev.length ? `<details open><summary>Evidence (${ev.length})</summary><pre>${esc(evidenceText(ev))}</pre></details>` : ''
      return `<div class="detail sev-${sev(f)}"><h3>${esc(summarize(f.type, (f as any).data))} <span class="score">${f.score ?? '—'}</span></h3><div class="badge">${esc(STATUS_LABEL[(f as any).status] ?? 'open')}</div>${reasonsHtml}${note}${evHtml}</div>`
    })
    .join('')

  const liveHtml = m.live.length
    ? `<table><thead><tr><th>Host</th><th>HTTP</th><th>Title</th><th>Server</th><th>IP</th></tr></thead><tbody>${m.live
        .map((s) => `<tr><td>${esc(s.host)}</td><td class="num">${s.httpStatus ?? ''}</td><td>${esc(s.title)}</td><td>${esc(s.server)}</td><td>${esc(s.ipAddress)}</td></tr>`)
        .join('')}</tbody></table>`
    : '<p class="muted">None probed live.</p>'

  const techHtml = m.tech
    ? `<ul>${[
        m.tech.os ? `<li><strong>OS:</strong> ${esc(m.tech.os)}</li>` : '',
        m.tech.server ? `<li><strong>Server:</strong> ${esc(m.tech.server)}</li>` : '',
        m.tech.cdn ? `<li><strong>CDN:</strong> ${esc(m.tech.cdn)}</li>` : '',
        m.tech.technologies?.length ? `<li><strong>Stack:</strong> ${esc(m.tech.technologies.join(', '))}</li>` : '',
      ]
        .filter(Boolean)
        .join('')}</ul>`
    : ''

  return `<!doctype html><html lang="en"><head><meta charset="utf-8">
<title>Recon report — ${esc(domain.host)}</title>
<style>
  :root { --ink:#0b0e14; --muted:#667; --line:#e2e5ea; --high:#c0392b; --medium:#c77d0a; --low:#3a6ea5; }
  * { box-sizing: border-box; }
  body { font: 14px/1.55 -apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif; color:#12151c; margin:0; padding:32px; max-width:960px; }
  h1 { font-size:24px; margin:0 0 4px; } h2 { font-size:17px; margin:28px 0 10px; border-bottom:2px solid var(--line); padding-bottom:4px; }
  h3 { font-size:14px; margin:0 0 6px; } .muted { color:var(--muted); }
  table { border-collapse:collapse; width:100%; margin:6px 0 12px; font-size:13px; }
  th,td { text-align:left; padding:6px 9px; border-bottom:1px solid var(--line); vertical-align:top; }
  th { background:#f6f7f9; font-size:11px; text-transform:uppercase; letter-spacing:.04em; color:#556; }
  td.num { text-align:right; font-variant-numeric:tabular-nums; } td.tags { color:var(--muted); font-size:11px; }
  .kv td:first-child { color:var(--muted); width:190px; } .kv { max-width:640px; }
  .legend { color:var(--muted); font-size:12px; } .exec { background:#f6f8fb; border:1px solid var(--line); border-radius:8px; padding:12px 14px; }
  .detail { border:1px solid var(--line); border-left-width:4px; border-radius:6px; padding:10px 12px; margin:10px 0; }
  .detail.sev-high { border-left-color:var(--high); } .detail.sev-medium { border-left-color:var(--medium); } .detail.sev-low { border-left-color:var(--low); }
  .detail .score { float:right; font-variant-numeric:tabular-nums; color:var(--muted); }
  .badge { display:inline-block; font-size:11px; color:var(--muted); margin-bottom:4px; }
  .why ul { margin:4px 0; padding-left:18px; } .why li { font-size:12px; }
  pre { background:#0b0e14; color:#e6edf3; padding:10px; border-radius:6px; overflow:auto; font-size:12px; white-space:pre-wrap; word-break:break-word; }
  details summary { cursor:pointer; font-size:12px; color:var(--muted); }
  footer { margin-top:32px; border-top:1px solid var(--line); padding-top:10px; color:var(--muted); font-size:12px; }
  @media print { body { padding:0; } h2 { break-after:avoid; } .detail { break-inside:avoid; } }
</style></head><body>
<h1>Recon report — ${esc(domain.host)}</h1>
<p class="muted">Generated ${esc(generatedAtIso)}</p>

<h2>Executive summary</h2>
<p class="exec">${esc(execSummary(m))}</p>

<h2>Scope &amp; authorization</h2>
<table class="kv"><tbody>
<tr><td>Target</td><td><code>${esc(domain.host)}</code></td></tr>
<tr><td>Label</td><td>${domain.label ? esc(domain.label) : '—'}</td></tr>
<tr><td>Mode</td><td>${esc(domain.mode)}</td></tr>
<tr><td>Scope allow</td><td>${scope.allow.length ? esc(scope.allow.join(', ')) : 'anything within the domain'}</td></tr>
<tr><td>Scope deny</td><td>${scope.deny.length ? esc(scope.deny.join(', ')) : '—'}</td></tr>
<tr><td>Authorization window</td><td>${esc(windowStr(domain))}</td></tr>
</tbody></table>
<p class="muted">Testing was performed under authorization for the target above.</p>

${m.methods.length ? `<h2>Methodology</h2><ul>${m.methods.map((x) => `<li>${esc(x)}</li>`).join('')}</ul>` : ''}

<h2>Summary</h2>
<ul>
<li><strong>Subdomains:</strong> ${m.subsTotal} (${m.live.length} live)</li>
<li><strong>Findings:</strong> ${m.reportable.length} reportable — ${m.high.length} high · ${m.medium.length} medium · ${m.low.length} low${m.noiseCount ? ` (${m.noiseCount} excluded)` : ''}</li>
<li><strong>Triage:</strong> ${m.counts.open} open · ${m.counts.confirmed} confirmed · ${m.counts.resolved} resolved</li>
<li><strong>Exposure:</strong> ${m.exposure.ips} exposed IP(s) · ${m.exposure.ports} open port(s) · ${m.exposure.cves} CVE(s)</li>
</ul>
<p class="legend">Severity by score: <strong>high</strong> ≥ 70 · <strong>medium</strong> 40–69 · <strong>low/info</strong> &lt; 40.</p>

${m.tech ? `<h2>Server &amp; technologies</h2>${techHtml}` : ''}

<h2>Findings — High (${m.high.length})</h2>${htmlTable(m.high)}
<h2>Findings — Medium (${m.medium.length})</h2>${htmlTable(m.medium)}
<h2>Findings — Low / info (${m.low.length})</h2>${htmlTable(m.low)}

${detailed.length ? `<h2>Finding detail (${detailed.length})</h2>${detailHtml}` : ''}

<h2>Live subdomains (${m.live.length})</h2>${liveHtml}

<footer>Generated by Recon Dashboard for authorized testing of ${esc(domain.host)}.</footer>
</body></html>`
}
