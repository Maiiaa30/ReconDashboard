// Email/DNS policy intel: parse the raw TXT/CAA records the tool already resolves
// into (a) osint findings (weak SPF/DMARC = spoofable; third-party senders reveal
// infra) and (b) candidate IP ranges from SPF ip4:/ip6: (infra pivots for
// exposure/ASN). All parsing is pure + unit-testable; the _dmarc lookup is
// injected. Passive — reads DNS only.

export type SpfAll = 'fail' | 'softfail' | 'neutral' | 'pass' | null

export interface SpfIntel {
  record: string | null
  includes: string[]
  ip4: string[]
  ip6: string[]
  redirect: string | null
  all: SpfAll // qualifier on the trailing `all` mechanism
}

export interface DmarcIntel {
  record: string | null
  policy: string | null // none | quarantine | reject
  subdomainPolicy: string | null
  pct: number | null
  rua: string[]
  ruf: string[]
}

export interface DnsIntelFinding {
  kind: string
  name: string
  severity: 'info' | 'low' | 'medium' | 'high'
  score: number
  evidence: string
}

export interface DnsIntel {
  spf: SpfIntel
  dmarc: DmarcIntel
  caaIssuers: string[]
  candidateRanges: string[]
  findings: DnsIntelFinding[]
}

// Parse the SPF record (the TXT starting v=spf1) into its mechanisms.
export function parseSpf(txt: string[]): SpfIntel {
  const record = txt.find((t) => /^v=spf1\b/i.test(t.trim())) ?? null
  const out: SpfIntel = { record, includes: [], ip4: [], ip6: [], redirect: null, all: null }
  if (!record) return out
  for (const term of record.trim().split(/\s+/)) {
    const m = term.match(/^([+\-~?]?)(include|ip4|ip6|redirect|all)[:=]?(.*)$/i)
    if (!m) continue
    const [, qual, mechRaw, val] = m
    const mech = mechRaw.toLowerCase()
    if (mech === 'include' && val) out.includes.push(val)
    else if (mech === 'ip4' && val) out.ip4.push(val)
    else if (mech === 'ip6' && val) out.ip6.push(val)
    else if (mech === 'redirect' && val) out.redirect = val
    else if (mech === 'all') out.all = qual === '-' ? 'fail' : qual === '~' ? 'softfail' : qual === '?' ? 'neutral' : 'pass'
  }
  return out
}

// Parse the DMARC record (v=DMARC1) into its policy tags.
export function parseDmarc(txt: string[]): DmarcIntel {
  const record = txt.find((t) => /^v=DMARC1\b/i.test(t.trim())) ?? null
  const out: DmarcIntel = { record, policy: null, subdomainPolicy: null, pct: null, rua: [], ruf: [] }
  if (!record) return out
  for (const part of record.split(';')) {
    const eq = part.indexOf('=')
    if (eq < 0) continue
    const key = part.slice(0, eq).trim().toLowerCase()
    const val = part.slice(eq + 1).trim()
    if (!val) continue
    if (key === 'p') out.policy = val.toLowerCase()
    else if (key === 'sp') out.subdomainPolicy = val.toLowerCase()
    else if (key === 'pct') out.pct = Number.isFinite(Number(val)) ? Number(val) : null
    else if (key === 'rua') out.rua = val.split(',').map((s) => s.trim()).filter(Boolean)
    else if (key === 'ruf') out.ruf = val.split(',').map((s) => s.trim()).filter(Boolean)
  }
  return out
}

// Distinct CA hostnames authorized to issue certs (from normalized CAA strings
// like "issue:letsencrypt.org").
export function parseCaaIssuers(caa: string[]): string[] {
  const out = new Set<string>()
  for (const r of caa) {
    const m = r.match(/^(issue|issuewild):(.+)$/i)
    if (m && m[2].trim() && m[2].trim() !== ';') out.add(m[2].trim())
  }
  return [...out]
}

// Turn parsed policy into osint findings (mostly low/info; a spoofable domain is
// medium). Pure — the caller persists them.
export function buildDnsIntelFindings(host: string, spf: SpfIntel, dmarc: DmarcIntel, caaIssuers: string[]): DnsIntelFinding[] {
  const out: DnsIntelFinding[] = []

  if (!spf.record) {
    out.push({ kind: 'dns_spf', name: 'No SPF record', severity: 'low', score: 30, evidence: `${host} publishes no SPF record — senders are unauthenticated (spoofing aid)` })
  } else {
    if (spf.all === 'pass') {
      out.push({ kind: 'dns_spf', name: 'SPF ends in +all (permissive)', severity: 'medium', score: 55, evidence: `SPF for ${host} ends in "+all" — any host is an authorized sender, defeating SPF` })
    }
    if (spf.includes.length) {
      out.push({ kind: 'dns_spf_senders', name: `SPF authorizes ${spf.includes.length} third-party sender(s)`, severity: 'info', score: 18, evidence: `include: ${spf.includes.join(', ')} — third-party mail/infra providers (recon pivots)` })
    }
    if (spf.ip4.length || spf.ip6.length) {
      out.push({ kind: 'dns_spf_ranges', name: `SPF exposes ${spf.ip4.length + spf.ip6.length} sender IP range(s)`, severity: 'info', score: 22, evidence: `ip4/ip6: ${[...spf.ip4, ...spf.ip6].join(', ')} — candidate infra ranges for ASN/exposure` })
    }
  }

  if (!dmarc.record) {
    out.push({ kind: 'dns_dmarc', name: 'No DMARC record', severity: 'medium', score: 50, evidence: `${host} has no DMARC policy — recipients cannot reject spoofed mail` })
  } else if (dmarc.policy === 'none' || dmarc.policy == null) {
    out.push({ kind: 'dns_dmarc', name: 'DMARC policy is none (monitor only)', severity: 'low', score: 40, evidence: `DMARC p=${dmarc.policy ?? '(unset)'} for ${host} — spoofed mail is monitored, not blocked` })
  } else {
    out.push({ kind: 'dns_dmarc', name: `DMARC policy is ${dmarc.policy}`, severity: 'info', score: 12, evidence: `DMARC p=${dmarc.policy}${dmarc.subdomainPolicy ? `, sp=${dmarc.subdomainPolicy}` : ''} for ${host}` })
  }

  if (!caaIssuers.length) {
    out.push({ kind: 'dns_caa', name: 'No CAA record', severity: 'info', score: 14, evidence: `${host} publishes no CAA record — any CA may issue certificates for it` })
  } else {
    out.push({ kind: 'dns_caa', name: `CAA authorizes ${caaIssuers.length} CA(s)`, severity: 'info', score: 10, evidence: `CAA issue: ${caaIssuers.join(', ')}` })
  }

  return out
}

// Gather the full DNS intel for a host: parse the apex TXT (SPF) + CAA already in
// hand, resolve _dmarc.<host> TXT, and build findings + candidate ranges.
export async function gatherDnsIntel(
  host: string,
  apexTxt: string[],
  caa: string[],
  resolveTxt: (h: string) => Promise<string[]>,
): Promise<DnsIntel> {
  const spf = parseSpf(apexTxt)
  let dmarcTxt: string[] = []
  try {
    dmarcTxt = await resolveTxt(`_dmarc.${host}`)
  } catch {
    /* NXDOMAIN / timeout → treat as no DMARC */
  }
  const dmarc = parseDmarc(dmarcTxt)
  const caaIssuers = parseCaaIssuers(caa)
  return {
    spf,
    dmarc,
    caaIssuers,
    candidateRanges: [...spf.ip4, ...spf.ip6],
    findings: buildDnsIntelFindings(host, spf, dmarc, caaIssuers),
  }
}
