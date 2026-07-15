import { guardedFetch } from './guard'

// Passive subdomain-takeover heuristic + a lightweight confirmation. A host whose
// CNAME points at a third-party service but returns 404 / no-response is a
// *candidate*. Confirmation fetches the host and matches the service's own
// "unclaimed" page — a match is proof the resource is claimable (critical).

interface TakeoverService {
  service: string
  cnameMatch: RegExp
}

const SERVICES: TakeoverService[] = [
  { service: 'github-pages', cnameMatch: /\.github\.io$/i },
  { service: 'heroku', cnameMatch: /\.herokuapp\.com$|\.herokudns\.com$/i },
  { service: 'aws-s3', cnameMatch: /\.s3[.-][a-z0-9-]*\.amazonaws\.com$|\.s3\.amazonaws\.com$/i },
  { service: 'aws-cloudfront', cnameMatch: /\.cloudfront\.net$/i },
  { service: 'azure', cnameMatch: /\.azurewebsites\.net$|\.cloudapp\.net$|\.blob\.core\.windows\.net$|\.trafficmanager\.net$/i },
  { service: 'fastly', cnameMatch: /\.fastly\.net$/i },
  { service: 'pantheon', cnameMatch: /\.pantheonsite\.io$/i },
  { service: 'shopify', cnameMatch: /\.myshopify\.com$/i },
  { service: 'zendesk', cnameMatch: /\.zendesk\.com$/i },
  { service: 'fly', cnameMatch: /\.fly\.dev$/i },
  { service: 'netlify', cnameMatch: /\.netlify\.app$|\.netlify\.com$/i },
  { service: 'ghost', cnameMatch: /\.ghost\.io$/i },
  { service: 'wpengine', cnameMatch: /\.wpengine\.com$/i },
  { service: 'readthedocs', cnameMatch: /\.readthedocs\.io$/i },
  { service: 'surge', cnameMatch: /\.surge\.sh$/i },
  { service: 'bitbucket', cnameMatch: /\.bitbucket\.io$/i },
]

export interface TakeoverHint {
  service: string
  cname: string
  confirmed?: boolean
}

// Service-specific "this resource is unclaimed" response bodies. A candidate whose
// live response contains its service's string is a CONFIRMED takeover (the target
// is serving the provider's claim-me page). Only high-confidence strings are here;
// a service with no reliable fingerprint stays a candidate (can't be confirmed).
export const TAKEOVER_FINGERPRINTS: Record<string, RegExp> = {
  'github-pages': /There isn't a GitHub Pages site here/i,
  heroku: /No such app|herokucdn\.com\/error-pages\/no-such-app\.html/i,
  'aws-s3': /NoSuchBucket|The specified bucket does not exist/i,
  fastly: /Fastly error: unknown domain/i,
  netlify: /Not Found - Request ID|Not found &middot; Netlify/i,
  shopify: /Sorry, this shop is currently unavailable/i,
  surge: /project not found/i,
  bitbucket: /Repository not found/i,
  pantheon: /The gods are wise|404 error unknown site/i,
  wpengine: /The site you were looking for couldn't be found/i,
  readthedocs: /unknown to Read the Docs/i,
  ghost: /Domain error|The thing you were looking for is no longer here/i,
  zendesk: /Help Center Closed|this help center no longer exists/i,
}

// Pure fingerprint match (testable without a network).
export function matchTakeoverFingerprint(service: string, body: string): boolean {
  const fp = TAKEOVER_FINGERPRINTS[service]
  return fp ? fp.test(body) : false
}

// Fetch the candidate host and confirm the takeover by matching the service's
// unclaimed-page string. SSRF-guarded (guardedFetch re-checks every hop). Returns
// false on any failure or a service with no fingerprint.
export async function confirmTakeover(host: string, service: string): Promise<boolean> {
  if (!TAKEOVER_FINGERPRINTS[service]) return false
  for (const scheme of ['https', 'http'] as const) {
    const res = await guardedFetch(`${scheme}://${host}/`, { timeoutMs: 8_000, maxBytes: 64 * 1024 })
    if (res && matchTakeoverFingerprint(service, res.body)) return true
  }
  return false
}

// Given a host's CNAME chain and its HTTP status, return a takeover candidate.
// We only flag when the host points at a known service AND did not serve a live
// 2xx/3xx page (no response, or a 404), which is the classic dangling pattern.
export function detectTakeover(cnames: string[], httpStatus: number | null): TakeoverHint | null {
  const dangling = httpStatus == null || httpStatus === 404
  if (!dangling) return null
  for (const cname of cnames) {
    const hit = SERVICES.find((s) => s.cnameMatch.test(cname.replace(/\.$/, '')))
    if (hit) return { service: hit.service, cname }
  }
  return null
}
