// Engagement scope matching. A scope is { allow, deny } lists whose entries are
// either a host pattern (exact host, or a parent domain that matches its
// subdomains) or a CIDR (matched against the target's resolved IPs). Used to
// keep active scans on authorized assets only.

import { isValidIp, normalizeHost } from './validate'

export interface ScopeConfig {
  allow: string[]
  deny: string[]
}

export function parseScopeConfig(raw: unknown): ScopeConfig {
  const obj = (raw && typeof raw === 'object' ? raw : {}) as Record<string, unknown>
  const clean = (v: unknown): string[] =>
    Array.isArray(v) ? v.map((s) => String(s).trim().toLowerCase()).filter(Boolean).slice(0, 500) : []
  return { allow: clean(obj.allow), deny: clean(obj.deny) }
}

export function scopeIsEmpty(s: ScopeConfig): boolean {
  return s.allow.length === 0 && s.deny.length === 0
}

/** True if any entry across allow/deny is a CIDR (so the caller must resolve IPs). */
export function scopeNeedsIps(s: ScopeConfig): boolean {
  return [...s.allow, ...s.deny].some(isCidr)
}

function isCidr(entry: string): boolean {
  return entry.includes('/')
}

// --- IP / CIDR ---------------------------------------------------------------

function ipv4ToInt(ip: string): bigint | null {
  const parts = ip.split('.')
  if (parts.length !== 4) return null
  let n = 0n
  for (const p of parts) {
    const o = Number(p)
    if (!Number.isInteger(o) || o < 0 || o > 255) return null
    n = (n << 8n) | BigInt(o)
  }
  return n
}

function expandIpv6(ip: string): bigint | null {
  // Strip a zone id and an embedded IPv4-mapped tail is not handled (rare here).
  const clean = ip.split('%')[0]
  if (clean.indexOf(':') === -1) return null
  const halves = clean.split('::')
  if (halves.length > 2) return null
  const head = halves[0] ? halves[0].split(':') : []
  const tail = halves.length === 2 && halves[1] ? halves[1].split(':') : []
  const missing = 8 - (head.length + tail.length)
  if (missing < 0 || (halves.length === 1 && head.length !== 8)) return null
  const groups = [...head, ...Array(halves.length === 2 ? missing : 0).fill('0'), ...tail]
  if (groups.length !== 8) return null
  let n = 0n
  for (const g of groups) {
    if (!/^[0-9a-f]{1,4}$/.test(g)) return null
    n = (n << 16n) | BigInt(parseInt(g, 16))
  }
  return n
}

function ipToBig(ip: string): { value: bigint; bits: number } | null {
  const v = ip.trim().toLowerCase()
  if (v.includes(':')) {
    const n = expandIpv6(v)
    return n === null ? null : { value: n, bits: 128 }
  }
  const n = ipv4ToInt(v)
  return n === null ? null : { value: n, bits: 32 }
}

/** True if ip falls inside cidr (e.g. "10.0.0.0/8" or "2001:db8::/32"). */
export function ipInCidr(ip: string, cidr: string): boolean {
  const slash = cidr.lastIndexOf('/')
  if (slash === -1) return false
  const base = cidr.slice(0, slash)
  const prefix = Number(cidr.slice(slash + 1))
  const a = ipToBig(ip)
  const b = ipToBig(base)
  if (!a || !b || a.bits !== b.bits) return false
  if (!Number.isInteger(prefix) || prefix < 0 || prefix > a.bits) return false
  if (prefix === 0) return true
  const shift = BigInt(a.bits - prefix)
  return a.value >> shift === b.value >> shift
}

// --- Host --------------------------------------------------------------------

/** Host matches an entry: exact, or a subdomain of the (parent-domain) entry. */
function hostMatchesEntry(host: string, entry: string): boolean {
  const h = normalizeHost(host)
  if (!h) return false
  return h === entry || h.endsWith(`.${entry}`)
}

function entryMatches(host: string, ips: string[], entry: string): boolean {
  if (isCidr(entry)) return ips.some((ip) => ipInCidr(ip, entry))
  if (isValidIp(entry)) return ips.includes(entry)
  return hostMatchesEntry(host, entry)
}

/**
 * Evaluate a target host (+ its resolved IPs) against a scope.
 * deny always wins; a non-empty allow list means the target must match it.
 */
export function evaluateScope(
  host: string,
  ips: string[],
  scope: ScopeConfig,
): { inScope: boolean; reason?: string } {
  for (const d of scope.deny) {
    if (entryMatches(host, ips, d)) return { inScope: false, reason: `matches deny rule "${d}"` }
  }
  if (scope.allow.length === 0) return { inScope: true }
  const ok = scope.allow.some((a) => entryMatches(host, ips, a))
  return ok ? { inScope: true } : { inScope: false, reason: 'not in the scope allow-list' }
}
