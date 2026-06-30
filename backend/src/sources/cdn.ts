// CDN / WAF fingerprinting. Used by origin-discovery to tell whether an IP is a
// CDN edge (Cloudflare etc.) or a likely real origin server. Public IP ranges
// and response-header signatures only — no exploitation.

// Published Cloudflare IPv4 ranges (cloudflare.com/ips). Edge IPs, not origins.
const CLOUDFLARE_V4 = [
  '173.245.48.0/20', '103.21.244.0/22', '103.22.200.0/22', '103.31.4.0/22',
  '141.101.64.0/18', '108.162.192.0/18', '190.93.240.0/20', '188.114.96.0/20',
  '197.234.240.0/22', '198.41.128.0/17', '162.158.0.0/15', '104.16.0.0/13',
  '104.24.0.0/14', '172.64.0.0/13', '131.0.72.0/22',
]

function ipToInt(ip: string): number | null {
  const parts = ip.split('.').map(Number)
  if (parts.length !== 4 || parts.some((p) => !Number.isInteger(p) || p < 0 || p > 255)) return null
  return ((parts[0] << 24) >>> 0) + (parts[1] << 16) + (parts[2] << 8) + parts[3]
}

function inCidr(ip: string, cidr: string): boolean {
  const [range, bitsStr] = cidr.split('/')
  const bits = Number(bitsStr)
  const ipInt = ipToInt(ip)
  const rangeInt = ipToInt(range)
  if (ipInt == null || rangeInt == null) return false
  const mask = bits === 0 ? 0 : (~0 << (32 - bits)) >>> 0
  return (ipInt & mask) === (rangeInt & mask)
}

/** Returns a CDN provider name if the IP is a known CDN edge, else null. */
export function cdnForIp(ip: string): string | null {
  if (CLOUDFLARE_V4.some((c) => inCidr(ip, c))) return 'cloudflare'
  return null
}

/** Detect WAF/CDN from response headers (covers providers without IP ranges). */
export function wafFromHeaders(headers: Headers): string | null {
  const get = (k: string) => headers.get(k)?.toLowerCase() ?? ''
  const server = get('server')
  if (get('cf-ray') || server.includes('cloudflare')) return 'cloudflare'
  if (get('x-sucuri-id') || get('x-sucuri-cache')) return 'sucuri'
  if (server.includes('akamai') || get('x-akamai-transformed') || get('x-akamai-request-id')) return 'akamai'
  if (server.includes('imperva') || get('x-iinfo') || get('x-cdn') === 'incapsula') return 'imperva-incapsula'
  if (get('x-amz-cf-id') || server.includes('cloudfront')) return 'aws-cloudfront'
  if (server.includes('fastly') || get('x-served-by').includes('cache')) return 'fastly'
  if (get('x-azure-ref') || server.includes('azure')) return 'azure-frontdoor'
  if (server.includes('sucuri')) return 'sucuri'
  return null
}

export function isCdnIp(ip: string): boolean {
  return cdnForIp(ip) !== null
}
