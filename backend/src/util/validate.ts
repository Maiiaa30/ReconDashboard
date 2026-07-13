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

// Private / loopback / link-local / ULA — addresses we must NOT fetch or
// screenshot (SSRF defense: a target's DNS could point a subdomain at an
// internal IP).
export function isInternalIp(input: string): boolean {
  const v = input.trim().toLowerCase()
  // IPv4-mapped IPv6 in dotted form (e.g. ::ffff:127.0.0.1). The dotted tail
  // doesn't match our hex-only IPv6 regex, so decode it explicitly first —
  // otherwise a mapped loopback/private address would slip past the guard.
  const mapped = v.match(/^::ffff:(\d{1,3}(?:\.\d{1,3}){3})$/)
  if (mapped) return isInternalIp(mapped[1])
  if (IPV4_RE.test(v)) {
    const [a, b] = v.split('.').map(Number)
    if (a === 10) return true
    if (a === 127) return true
    if (a === 0) return true
    if (a === 172 && b >= 16 && b <= 31) return true
    if (a === 192 && b === 168) return true
    if (a === 169 && b === 254) return true // link-local
    if (a === 100 && b >= 64 && b <= 127) return true // CGNAT
    if (a >= 224) return true // multicast / reserved
    return false
  }
  if (IPV6_RE.test(v)) {
    if (v === '::1' || v === '::') return true
    if (v.startsWith('fe80') || v.startsWith('fc') || v.startsWith('fd')) return true // link-local / ULA
    // IPv4 embedded in the low 32 bits: IPv4-mapped (::ffff:a.b.c.d) and the
    // compressed HEX form the URL parser actually produces (::ffff:7f00:1),
    // IPv4-compatible (::a.b.c.d), and the NAT64 well-known prefix 64:ff9b::/96.
    // Decode the embedded IPv4 and judge THAT — the dotted-only check above never
    // sees the hex form, which let ::ffff:127.0.0.1 (loopback) slip the guard.
    const g = ipv6Groups(v)
    if (g) {
      const embedsV4 =
        (g[0] === 0 && g[1] === 0 && g[2] === 0 && g[3] === 0 && g[4] === 0 && (g[5] === 0xffff || g[5] === 0)) ||
        (g[0] === 0x64 && g[1] === 0xff9b)
      if (embedsV4 && !(g[6] === 0 && g[7] === 0)) {
        return isInternalIp(`${g[6] >> 8}.${g[6] & 0xff}.${g[7] >> 8}.${g[7] & 0xff}`)
      }
    }
    return false
  }
  return false
}

// Expand a (possibly compressed / IPv4-tailed) IPv6 into its 8 16-bit groups,
// or null if it isn't parseable. Used to unwrap IPv4-in-IPv6 forms for the SSRF
// guard so an internal address can't hide inside an IPv6 literal.
function ipv6Groups(input: string): number[] | null {
  let s = input.trim().toLowerCase()
  if (!IPV6_RE.test(s)) return null
  // Convert a trailing dotted IPv4 (::ffff:127.0.0.1) into two hex groups.
  const dotted = s.match(/^(.*:)(\d{1,3}(?:\.\d{1,3}){3})$/)
  if (dotted) {
    const o = dotted[2].split('.').map(Number)
    if (o.some((n) => n > 255)) return null
    s = dotted[1] + ((o[0] << 8) | o[1]).toString(16) + ':' + ((o[2] << 8) | o[3]).toString(16)
  }
  const halves = s.split('::')
  if (halves.length > 2) return null
  const head = halves[0] ? halves[0].split(':') : []
  const tail = halves.length === 2 ? (halves[1] ? halves[1].split(':') : []) : null
  let groups: string[]
  if (tail === null) {
    groups = head
  } else {
    const fill = 8 - head.length - tail.length
    if (fill < 0) return null
    groups = [...head, ...Array(fill).fill('0'), ...tail]
  }
  if (groups.length !== 8) return null
  const nums = groups.map((x) => parseInt(x || '0', 16))
  return nums.some((n) => Number.isNaN(n) || n < 0 || n > 0xffff) ? null : nums
}

/** A host belongs to a domain if it equals it or is a subdomain of it. */
export function hostBelongsToDomain(host: string, domain: string): boolean {
  const h = normalizeHost(host)
  const d = normalizeDomain(domain)
  if (!h) return false
  return h === d || h.endsWith(`.${d}`)
}
