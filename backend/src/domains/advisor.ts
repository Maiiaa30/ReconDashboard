import { config } from '../config'
import { llmCompleteJson } from '../util/llm'
import { listFindings } from '../findings/store'
import { listSubdomains } from '../subdomains/store'
import { hostBelongsToDomain } from '../util/validate'
import { getDomain } from './store'
import { correlateDomain } from './correlate'
import { buildMethodology } from '../skills/methodology'

type Finding = ReturnType<typeof listFindings>[number]

// AI intel advisor: reads the ALREADY-collected recon (attack-path correlation,
// findings, subdomains, discovered URLs/params, tech fingerprint) and asks the
// LLM for a prioritized, structured testing plan — what to look at first, which
// hosts/params are injection/XSS candidates, quick wins, deeper digs. Grounded
// strictly in stored data; narrative-only (never touches scoring). Fail-soft:
// returns null so the caller reports 502/503 and the UI degrades gracefully.

// Runnable actions the advisor may attach to a suggestion. Constrained to real,
// in-app capabilities so the "Run" button never points at a tool we can't launch
// (the LLM often suggests external tools like Metasploit/Burp — those get no
// action). Every action still passes through assertScanAllowed on Run.
export const ACTION_KINDS = ['nmap', 'naabu', 'nuclei', 'ffuf', 'dalfox', 'sslscan', 'katana', 'owasp'] as const
export type ActionKind = (typeof ACTION_KINDS)[number]
export interface AdviceAction {
  kind: ActionKind
  target: string
}

export interface AdvicePriority {
  target: string
  risk: 'high' | 'medium' | 'low'
  why: string
  tests: string[]
  action?: AdviceAction
}
export interface AdviceInjection {
  target: string
  param?: string
  type: string
  why: string
  action?: AdviceAction
}
export interface AdviceItem {
  item: string
  why: string
}
export interface IntelAdvice {
  summary: string
  priorities: AdvicePriority[]
  injection: AdviceInjection[]
  quickWins: AdviceItem[]
  deeperDigs: AdviceItem[]
}

// Pull parameterized URLs (candidate injection points) out of the passive-recon
// corpus (wayback / commoncrawl) plus any finding URL that carries a query string.
function paramUrls(findings: Finding[]): string[] {
  const out = new Set<string>()
  for (const f of findings) {
    const d = (f.data ?? {}) as any
    for (const src of ['wayback', 'commoncrawl']) {
      if (Array.isArray(d?.[src]?.withParams)) for (const u of d[src].withParams) out.add(String(u))
    }
    for (const key of ['url', 'matched']) {
      if (typeof d[key] === 'string' && d[key].includes('?')) out.add(d[key])
    }
  }
  return [...out]
}

function desc(f: Finding): string {
  const d = (f.data ?? {}) as any
  return String(
    d.name ?? d.title ?? d.category ?? d.ip ?? d.host ?? d.url ?? d.matched ?? f.type,
  ).slice(0, 160)
}

// Compact, token-bounded facts bundle. Everything here is stored data — the LLM
// is told to ground strictly in it and invent nothing.
export function buildIntelFacts(domainId: number): string {
  const domain = getDomain(domainId)
  const host = domain?.host ?? `#${domainId}`
  const findings = listFindings({ domainId, limit: 2000 })
  const subs = listSubdomains(domainId)
  const live = subs.filter((s) => s.httpStatus != null)
  const paths = correlateDomain(domainId)

  const lines: string[] = []
  lines.push(`Target: ${host}`)
  lines.push(`Subdomains: ${subs.length} (${live.length} live)`)

  const tech = new Set<string>()
  for (const f of findings) for (const t of f.tags ?? []) if (t.startsWith('tech:')) tech.add(t.slice(5))
  if (tech.size) lines.push(`Tech fingerprint: ${[...tech].slice(0, 12).join(', ')}`)

  if (paths.length) {
    lines.push('', 'Assets (host(s) -> IP -> ports -> CVEs), worst first:')
    for (const p of paths.slice(0, 15)) {
      const hosts = p.hosts.length ? p.hosts.slice(0, 3).join(', ') : '(no host)'
      const cdn = p.cdn ? ` [${p.cdn} edge]` : ''
      const asn = p.asn ? ` AS${p.asn}` : ''
      const ports = p.ports.length ? p.ports.slice(0, 12).join('/') : 'none'
      const cve = p.cveCount
        ? `${p.cveCount} CVE(s)${p.worstCvss ? ` worst CVSS ${p.worstCvss}` : ''}${p.kev ? ' [KEV]' : ''}`
        : 'no known CVEs'
      lines.push(`- ${hosts} -> ${p.ip}${cdn}${asn} | ports: ${ports} | ${cve}`)
    }
  }

  // Injection / reflected-input signals the app already found.
  const inj = findings.filter((f) => {
    const d = (f.data ?? {}) as any
    const name = String(d.name ?? d.title ?? '').toLowerCase()
    const cat = String(d.category ?? '')
    const tags = (f.tags ?? []).join(' ').toLowerCase()
    if (f.type === 'owasp') return cat.startsWith('A03') || /xss|redirect|cors|inject/.test(name)
    if (f.type === 'tool') return /dalfox|xss/.test(`${d.tool ?? ''} ${name}`)
    if (f.type === 'nuclei') return /xss|inject|redirect|traversal|sqli/.test(`${name} ${tags}`)
    return false
  })
  if (inj.length) {
    lines.push('', 'Injection / reflected-input findings:')
    for (const f of inj.slice(0, 20)) {
      const d = (f.data ?? {}) as any
      const where = d.url ? ` @ ${d.url}` : d.matched ? ` @ ${d.matched}` : ''
      lines.push(`- [${f.score ?? '—'}] ${f.type}: ${desc(f)}${where}`)
    }
  }

  const purls = paramUrls(findings).slice(0, 25)
  if (purls.length) {
    lines.push('', 'Known URLs with query parameters (candidate injection points):')
    for (const u of purls) lines.push(`- ${u}`)
  }

  const others = findings
    .filter((f) => (f.score ?? 0) >= 40 && !inj.includes(f))
    .sort((a, b) => (b.score ?? 0) - (a.score ?? 0))
    .slice(0, 15)
  if (others.length) {
    lines.push('', 'Other notable findings:')
    for (const f of others) lines.push(`- [${f.score ?? '—'}] ${f.type}: ${desc(f)}`)
  }

  // Methodology coverage — so the advisor prioritises the UNCOVERED steps of the
  // skills that apply to this target instead of re-suggesting done work.
  const applicable = buildMethodology(domainId).skills.filter((s) => s.applicable)
  if (applicable.length) {
    lines.push('', 'Methodology coverage (applicable skills — prioritise what is still TODO):')
    for (const s of applicable) {
      const done = s.steps.filter((st) => st.status === 'found' || st.status === 'done').map((st) => st.label)
      const todo = s.steps.filter((st) => st.status === 'todo' || st.status === 'running').map((st) => st.label)
      lines.push(`- ${s.name} (${s.coverage}%): done [${done.join(', ') || 'none'}]; TODO [${todo.join(', ') || 'none'}]`)
    }
  }

  return lines.join('\n')
}

const SYSTEM =
  'You are a senior offensive-security operator triaging reconnaissance data for an AUTHORIZED penetration ' +
  'test. From the collected recon facts, produce a prioritized, actionable testing plan. Ground EVERYTHING ' +
  'strictly in the facts provided — do NOT invent hosts, IPs, CVEs, parameters, or findings that are not ' +
  'present. Be specific and technical: name the concrete host/param to test and the tool or technique, not ' +
  'generic advice. If a "Methodology coverage" section is present, PRIORITISE the steps still marked TODO for ' +
  'the skills that apply — do not re-suggest work already done. Respond with ONLY a JSON object (no prose, no ' +
  'markdown fences) of this exact shape:\n' +
  '{\n' +
  '  "summary": "1-2 sentence read of the attack surface",\n' +
  '  "priorities": [ { "target": "host or IP", "risk": "high|medium|low", "why": "grounded reason", "tests": ["specific test/tool", ...], "action": { "kind": "nmap|naabu|nuclei|ffuf|dalfox|sslscan|katana|owasp", "target": "hostname" } } ],\n' +
  '  "injection": [ { "target": "url or host", "param": "param name or empty", "type": "XSS|Open Redirect|SQLi|CORS|SSRF|Path Traversal", "why": "why it is a candidate", "action": { "kind": "dalfox|owasp|nuclei", "target": "hostname" } } ],\n' +
  '  "quickWins": [ { "item": "low-effort high-signal action", "why": "reason" } ],\n' +
  '  "deeperDigs": [ { "item": "action needing manual follow-up", "why": "reason" } ]\n' +
  '}\n' +
  'The optional "action" wires the suggestion to an in-app scanner. Add it ONLY when one of these tools ' +
  '(nmap, naabu, nuclei, ffuf, dalfox, sslscan, katana, owasp) directly applies; OMIT it for external tools ' +
  '(Metasploit, Burp, ZAP, manual review). The action "target" MUST be a hostname within this engagement (the ' +
  'domain itself or a listed subdomain) — never a raw IP address or a full URL. At most 6 items per array. ' +
  'Return an empty array for any section with nothing grounded.'

function str(x: unknown): string {
  return typeof x === 'string' ? x : x == null ? '' : String(x)
}
function arr(x: unknown): any[] {
  return Array.isArray(x) ? x : []
}
function normItems(x: unknown): AdviceItem[] {
  return arr(x)
    .slice(0, 6)
    .map((i) => ({ item: str(i?.item).slice(0, 300), why: str(i?.why).slice(0, 400) }))
    .filter((i) => i.item)
}

// Validate an LLM-proposed action against the real capability allow-list and the
// engagement's own hostnames. A URL or IP the model may have put in `target` is
// reduced to a bare host; anything not belonging to the domain is dropped (no
// button). The scan endpoint re-checks everything on Run — this just avoids dead
// or out-of-scope buttons in the UI.
function normAction(raw: unknown, domainHost: string): AdviceAction | undefined {
  if (!raw || typeof raw !== 'object') return undefined
  const kind = str((raw as any).kind).trim().toLowerCase()
  if (!(ACTION_KINDS as readonly string[]).includes(kind)) return undefined
  // owasp always runs against the domain host regardless of the suggested target.
  if (kind === 'owasp') return { kind: kind as ActionKind, target: domainHost }
  let target = str((raw as any).target).trim().toLowerCase()
  if (target.includes('://')) {
    try {
      target = new URL(target).hostname
    } catch {
      /* fall through to manual strip */
    }
  }
  target = target.replace(/^https?:\/\//, '').split('/')[0].split(':')[0].replace(/^\*\./, '')
  if (!target) target = domainHost
  if (target !== domainHost && !hostBelongsToDomain(target, domainHost)) return undefined
  return { kind: kind as ActionKind, target }
}

function normalize(raw: any, domainHost: string): IntelAdvice {
  const risk = (r: unknown): 'high' | 'medium' | 'low' =>
    r === 'high' || r === 'low' ? r : 'medium'
  return {
    summary: str(raw?.summary).slice(0, 600),
    priorities: arr(raw?.priorities)
      .slice(0, 6)
      .map((t) => ({
        target: str(t?.target).slice(0, 200),
        risk: risk(t?.risk),
        why: str(t?.why).slice(0, 400),
        tests: arr(t?.tests)
          .slice(0, 8)
          .map((x) => str(x).slice(0, 200))
          .filter(Boolean),
        action: normAction(t?.action, domainHost),
      }))
      .filter((t) => t.target || t.why),
    injection: arr(raw?.injection)
      .slice(0, 6)
      .map((t) => ({
        target: str(t?.target).slice(0, 300),
        param: str(t?.param).slice(0, 120) || undefined,
        type: str(t?.type).slice(0, 60) || 'unknown',
        why: str(t?.why).slice(0, 400),
        action: normAction(t?.action, domainHost),
      }))
      .filter((t) => t.target),
    quickWins: normItems(raw?.quickWins),
    deeperDigs: normItems(raw?.deeperDigs),
  }
}

export async function adviseIntel(domainId: number): Promise<{ advice: IntelAdvice; model: string } | null> {
  const domain = getDomain(domainId)
  const facts = buildIntelFacts(domainId)
  const raw = await llmCompleteJson<Partial<IntelAdvice>>(SYSTEM, facts, 1400)
  if (!raw) return null
  return { advice: normalize(raw, domain?.host ?? ''), model: config.llm.model }
}
