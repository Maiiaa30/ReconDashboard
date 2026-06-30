// Strict input validation. Every domain/host/IP that flows into an external
// request or a subprocess argument MUST pass through here first.

// Registrable domain: one or more labels + a TLD. No scheme, port, path, wildcard.
const DOMAIN_RE = /^(?=.{1,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/

// Hostname (subdomain): like a domain but underscores are allowed in labels
// because passive sources legitimately return names like _dmarc.example.com.
const HOSTNAME_RE = /^(?=.{1,253}$)([a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?\.)+[a-z]{2,63}$/

const IPV4_RE = /^(25[0-5]|2[0-4]\d|1?\d?\d)(\.(25[0-5]|2[0-4]\d|1?\d?\d)){3}$/
const IPV6_RE = /^(([0-9a-f]{1,4}:){7}[0-9a-f]{1,4}|([0-9a-f]{1,4}:){1,7}:|([0-9a-f]{1,4}:){1,6}:[0-9a-f]{1,4}|([0-9a-f]{1,4}:){1,5}(:[0-9a-f]{1,4}){1,2}|([0-9a-f]{1,4}:){1,4}(:[0-9a-f]{1,4}){1,3}|([0-9a-f]{1,4}:){1,3}(:[0-9a-f]{1,4}){1,4}|([0-9a-f]{1,4}:){1,2}(:[0-9a-f]{1,4}){1,5}|[0-9a-f]{1,4}:((:[0-9a-f]{1,4}){1,6})|:((:[0-9a-f]{1,4}){1,7}|:))$/

export function normalizeDomain(input: string): string {
  return input.trim().toLowerCase().replace(/\.$/, '')
}

export function isValidDomain(input: string): boolean {
  return DOMAIN_RE.test(normalizeDomain(input))
}

/** Normalize a host returned by a passive source. Returns null if unusable. */
export function normalizeHost(input: string): string | null {
  let h = input.trim().toLowerCase()
  if (!h) return null
  h = h.replace(/^\*\./, '') // crt.sh wildcard entries
  h = h.replace(/\.$/, '')
  if (h.length > 253) return null
  return HOSTNAME_RE.test(h) ? h : null
}

export function isValidHostname(input: string): boolean {
  return normalizeHost(input) !== null
}

export function isValidIp(input: string): boolean {
  const v = input.trim().toLowerCase()
  return IPV4_RE.test(v) || IPV6_RE.test(v)
}

/** A host belongs to a domain if it equals it or is a subdomain of it. */
export function hostBelongsToDomain(host: string, domain: string): boolean {
  const h = normalizeHost(host)
  const d = normalizeDomain(domain)
  if (!h) return false
  return h === d || h.endsWith(`.${d}`)
}
