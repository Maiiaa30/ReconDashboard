// Content-Security-Policy analysis — pure, so it is unit-testable without a
// network. A present CSP is only as good as its directives; the common failures
// (an XSS-defeating `'unsafe-inline'` with no nonce/hash, a wildcard script
// source, no `object-src`/`base-uri`) let a reflected/stored XSS still execute.
// This parses the header the OWASP active check already collected — zero extra
// traffic — and reports the weaknesses with a deliberate false-positive guard.

export type CspSeverity = 'info' | 'low' | 'medium' | 'high' | 'critical'

export interface CspIssue {
  name: string
  severity: CspSeverity
  evidence: string
}

// A source expression that makes inline script actually run despite a nonce/hash
// being present would be a browser bug; per spec, once a nonce or hash is present
// in a source list, `'unsafe-inline'` is IGNORED. So flag unsafe-inline ONLY when
// no nonce/hash accompanies it — that is the real, exploitable case.
const NONCE_OR_HASH = /'(nonce-[^']+|sha(?:256|384|512)-[^']+)'/i

// Parse a CSP header into a directive → tokens map (lowercased directive names).
function parseDirectives(csp: string): Map<string, string[]> {
  const out = new Map<string, string[]>()
  for (const part of csp.split(';')) {
    const tokens = part.trim().split(/\s+/).filter(Boolean)
    if (!tokens.length) continue
    const name = tokens[0].toLowerCase()
    out.set(name, tokens.slice(1))
  }
  return out
}

export function analyzeCsp(csp: string): CspIssue[] {
  const issues: CspIssue[] = []
  const dirs = parseDirectives(csp)
  if (dirs.size === 0) return issues

  // The effective script source is script-src, falling back to default-src.
  const scriptDir = dirs.has('script-src') ? 'script-src' : dirs.has('default-src') ? 'default-src' : null
  const scriptSrc = scriptDir ? dirs.get(scriptDir)! : []
  const scriptSrcRaw = scriptSrc.join(' ')
  const defaultSrc = dirs.get('default-src') ?? []
  const defaultIsNone = defaultSrc.length === 1 && defaultSrc[0].toLowerCase() === "'none'"

  if (scriptDir) {
    const hasUnsafeInline = scriptSrc.some((t) => t.toLowerCase() === "'unsafe-inline'")
    // FP guard: a nonce/hash in the SAME source list neutralizes 'unsafe-inline'.
    if (hasUnsafeInline && !NONCE_OR_HASH.test(scriptSrcRaw)) {
      issues.push({
        name: `CSP allows 'unsafe-inline' script (no nonce/hash)`,
        severity: 'medium',
        evidence: `${scriptDir} ${scriptSrcRaw} — inline script executes; a reflected/stored XSS is not mitigated`,
      })
    }
    if (scriptSrc.some((t) => t.toLowerCase() === "'unsafe-eval'")) {
      issues.push({ name: `CSP allows 'unsafe-eval' script`, severity: 'low', evidence: `${scriptDir} permits eval()-family sinks` })
    }
    // A wildcard (or bare scheme) script source lets an attacker host script anywhere.
    const wild = scriptSrc.find((t) => t === '*' || /^https?:$/i.test(t) || t.toLowerCase() === 'data:')
    if (wild) {
      issues.push({ name: `CSP script source is a wildcard (${wild})`, severity: 'medium', evidence: `${scriptDir} ${scriptSrcRaw} — script may be loaded from any origin` })
    }
  } else {
    // No script-src and no default-src at all: CSP constrains nothing for script.
    issues.push({ name: 'CSP does not restrict script-src', severity: 'medium', evidence: 'neither script-src nor default-src is set' })
  }

  // object-src controls plugins/embeds — a classic XSS vector when unset.
  if (!dirs.has('object-src') && !defaultIsNone) {
    issues.push({ name: `CSP missing object-src`, severity: 'low', evidence: `no object-src (and default-src is not 'none') — plugin-based injection is unconstrained` })
  }
  // base-uri controls <base href>; without it an injected <base> can hijack
  // relative script URLs even under a nonce policy.
  if (!dirs.has('base-uri')) {
    issues.push({ name: `CSP missing base-uri`, severity: 'low', evidence: `no base-uri — an injected <base> tag can redirect relative resource loads` })
  }

  return issues
}

// Parse an HSTS header value and report it as weak if the max-age is short or it
// omits includeSubDomains. Returns null when the policy is adequate (or absent —
// a missing HSTS is reported by the separate missing-header check).
export function analyzeHsts(value: string | null): CspIssue | null {
  if (!value) return null
  const m = /max-age\s*=\s*(\d+)/i.exec(value)
  const maxAge = m ? Number(m[1]) : 0
  const includesSub = /includeSubDomains/i.test(value)
  const SIX_MONTHS = 15_552_000 // seconds
  const reasons: string[] = []
  if (maxAge < SIX_MONTHS) reasons.push(`max-age=${maxAge} is under 6 months`)
  if (!includesSub) reasons.push('no includeSubDomains')
  if (!reasons.length) return null
  return { name: 'Weak HSTS policy', severity: 'low', evidence: `Strict-Transport-Security: ${value} — ${reasons.join('; ')}` }
}
