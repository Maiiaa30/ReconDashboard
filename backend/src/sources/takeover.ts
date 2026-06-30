// Passive subdomain-takeover heuristic. A host whose CNAME points at a
// third-party service (GitHub Pages, Heroku, S3, etc.) but which returns 404 /
// no-response is a *candidate* for takeover (the underlying resource may be
// unclaimed). This is a HINT, not confirmation — nuclei takeover templates (via
// the OWASP tab) do the real verification.

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
