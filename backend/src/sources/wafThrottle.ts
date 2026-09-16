// Per-tool request throttling for a target known to sit behind a WAF. Unlike
// sqlmap (which has payload tamper), nuclei/ffuf/dalfox slip a WAF mainly by not
// tripping its rate-based rules — so when we already know a WAF fronts the host
// (from the stored subdomains.waf / wafBrand, no extra probing), we lower the
// request rate and add jitter. The clearance-cookie handling stays orthogonal.
//
// Brands are matched by keyword against whatever label we stored — the header
// slug ('cloudflare') or a wafw00f brand ('Cloudflare (Cloudflare Inc.)').

export interface WafThrottle {
  rateLimit: number // nuclei -rl : max requests/second
  ffufDelay: string // ffuf -p : seconds between requests (range = jitter)
  dalfoxWorker: number // dalfox --worker : concurrency
  dalfoxDelayMs: number // dalfox --delay : ms between requests
  reason: string
}

// Aggressive rate engines get the heaviest throttle; lighter CDNs a moderate
// one; an unknown-but-present WAF a light default.
const AGGRESSIVE: WafThrottle = { rateLimit: 5, ffufDelay: '0.3-0.7', dalfoxWorker: 5, dalfoxDelayMs: 400, reason: 'aggressive-WAF throttle' }
const MODERATE: WafThrottle = { rateLimit: 10, ffufDelay: '0.1-0.3', dalfoxWorker: 10, dalfoxDelayMs: 200, reason: 'WAF throttle' }
const LIGHT: WafThrottle = { rateLimit: 15, ffufDelay: '0.1-0.2', dalfoxWorker: 15, dalfoxDelayMs: 100, reason: 'light WAF throttle' }

const AGGRESSIVE_KEYWORDS = ['cloudflare', 'akamai', 'imperva', 'incapsula']
const MODERATE_KEYWORDS = ['sucuri', 'aws', 'fastly', 'modsecurity', 'mod_security', 'f5', 'big-ip']

/**
 * Throttle profile for a stored WAF brand, or `null` when no WAF is known (so
 * the caller runs at full speed). A present-but-unrecognized brand gets LIGHT.
 */
export function throttleForBrand(brand: string | null | undefined): WafThrottle | null {
  if (!brand) return null
  const label = brand.toLowerCase()
  if (AGGRESSIVE_KEYWORDS.some((k) => label.includes(k))) return AGGRESSIVE
  if (MODERATE_KEYWORDS.some((k) => label.includes(k))) return MODERATE
  return LIGHT
}
