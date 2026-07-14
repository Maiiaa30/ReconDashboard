// IDOR / broken-authorization helper. No scanner finds these reliably because
// "should identity A be able to see object B?" is a SEMANTIC question. This tool
// does the MECHANICAL part — replay the same object request under three identities
// (A = the template's own creds, B = an operator-supplied second account, and
// credential-stripped = anonymous) and diff the responses — and leaves the
// judgment to the operator. Every result is needs-review; nothing is auto-confirmed.

export const ID_MARKER = '{{ID}}'

export type AuthzVerdict = 'likely_idor' | 'missing_authz' | 'enforced' | 'inconclusive'

export interface IdentityResult {
  status: number
  length: number
  error?: string
}

// Plain boolean (not a type guard) — a `!isOk(x)` guard would narrow a non-null
// IdentityResult to `never`, which TS then rejects on property access.
const isOk = (r: IdentityResult | null | undefined): boolean => !!r && !r.error && r.status >= 200 && r.status < 300

// Two responses "match" when their lengths are within 10% — the same object body,
// allowing for small per-request variance (timestamps, csrf tokens). Length that
// tracks the object id is the core IDOR tell: identity B receiving A's byte-count
// for A's object means B read A's data.
function sameLength(x: number, y: number): boolean {
  const m = Math.max(x, y, 1)
  return Math.abs(x - y) / m <= 0.1
}

// Verdict for one object id from the three identity responses. `b` / `none` may be
// null when that identity wasn't tested (no identity B supplied).
export function authzVerdict(a: IdentityResult, b: IdentityResult | null, none: IdentityResult | null): { verdict: AuthzVerdict; reason: string } {
  if (!isOk(a)) {
    return { verdict: 'inconclusive', reason: `identity A did not get a 2xx (status ${a.status}${a.error ? `, ${a.error}` : ''}) — can't baseline this object` }
  }
  // Anonymous access to an authenticated object is the most severe outcome.
  if (none && isOk(none) && sameLength(a.length, none.length)) {
    return { verdict: 'missing_authz', reason: `credential-stripped request also returned 2xx with a matching body (${none.length}B vs ${a.length}B) — object is reachable without authentication` }
  }
  // Identity B reading A's object with a matching body = classic IDOR.
  if (b && isOk(b) && sameLength(a.length, b.length)) {
    return { verdict: 'likely_idor', reason: `identity B returned 2xx with a body matching A's (${b.length}B vs ${a.length}B) — B appears to read A's object` }
  }
  // B (and anonymous) are refused while A succeeds = access control working.
  if (b && !isOk(b) && !isOk(none)) {
    return { verdict: 'enforced', reason: `identity B (${b.status}) and anonymous (${none ? none.status : 'n/a'}) were refused while A succeeded — access control looks enforced` }
  }
  return { verdict: 'inconclusive', reason: 'mixed signals — review the per-identity responses manually' }
}

// Substitute the object id into the template's {{ID}} markers.
export function applyId(text: string | undefined, id: string): string | undefined {
  if (text == null) return text
  return text.split(ID_MARKER).join(id)
}

// Does the template mark an object id anywhere?
export function hasIdMarker(parts: (string | undefined)[]): boolean {
  return parts.some((p) => typeof p === 'string' && p.includes(ID_MARKER))
}
