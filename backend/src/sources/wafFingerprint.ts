import { run, ToolNotFoundError } from '../util/exec'
import { assertPublicHost, guardedFetchRaw } from './guard'
import { detectWaf } from './httpProbe'

// Richer WAF identification than the header-only `detectWaf`. Prefers wafw00f
// (150+ signatures, actively probes for the vendor's block-page fingerprint) and
// falls back to our header check when the binary is unavailable — matching the
// existing best-effort-tool pattern (a missing binary just yields a thinner
// result, never an error).
//
// VERSION: modern cloud WAFs (Cloudflare/Akamai/Imperva/AWS/Fastly) are
// versionless SaaS — there is no version to report. Self-hosted engines
// (ModSecurity, F5 BIG-IP ASM) occasionally leak one in the Server header; we
// surface it best-effort and leave it null otherwise. Never fabricated.

export interface WafFingerprint {
  detected: boolean
  brand: string | null // e.g. "Cloudflare", "Imperva SecureSphere", or a slug
  manufacturer: string | null // e.g. "Cloudflare Inc." (wafw00f only)
  version: string | null // best-effort; usually null (SaaS WAFs have none)
  source: 'wafw00f' | 'headers' | 'none'
}

const NONE: WafFingerprint = { detected: false, brand: null, manufacturer: null, version: null, source: 'none' }

// wafw00f -f json emits an array of objects; field names have drifted across
// releases, so read both the current and older shapes.
interface Wafw00fEntry {
  detected?: boolean
  firewall?: string
  waf?: string
  manufacturer?: string
  vendor?: string
}

// Pull the first JSON array out of wafw00f stdout, tolerating any banner text a
// build might print before it.
export function parseWafw00f(stdout: string): WafFingerprint | null {
  const start = stdout.indexOf('[')
  const end = stdout.lastIndexOf(']')
  if (start === -1 || end <= start) return null
  let entries: Wafw00fEntry[]
  try {
    entries = JSON.parse(stdout.slice(start, end + 1))
  } catch {
    return null
  }
  if (!Array.isArray(entries)) return null
  const hit = entries.find((e) => e && e.detected && (e.firewall ?? e.waf)) ?? entries.find((e) => e && (e.firewall ?? e.waf))
  const brand = (hit?.firewall ?? hit?.waf ?? '').trim()
  if (!hit || !brand || /^(generic|none)$/i.test(brand)) return null
  return {
    detected: true,
    brand,
    manufacturer: (hit.manufacturer ?? hit.vendor ?? null) || null,
    version: null,
    source: 'wafw00f',
  }
}

// Best-effort version from the Server header only — e.g. "Mod_Security/2.9.3" or
// a BIG-IP build token. Returns null for the common SaaS WAFs (no version).
async function versionFromHeaders(url: string, signal?: AbortSignal): Promise<string | null> {
  const res = await guardedFetchRaw(url, { method: 'GET', signal }).catch(() => null)
  const server = res?.headers.get('server') ?? ''
  const m = server.match(/mod_security\/?\s*([\d.]+)/i) ?? server.match(/big-?ip[^\d]*([\d.]+)/i)
  return m?.[1] ? m[1] : null
}

// Header-only fallback: reuse detectWaf, then best-effort version.
async function headerFingerprint(scheme: string, host: string, signal?: AbortSignal): Promise<WafFingerprint> {
  const url = `${scheme}://${host}`
  const res = await guardedFetchRaw(url, { method: 'GET', signal }).catch(() => null)
  if (!res) return NONE
  const brand = detectWaf(res.headers, res.body)
  if (!brand) return NONE
  const m = (res.headers.get('server') ?? '').match(/mod_security\/?\s*([\d.]+)/i)
  return { detected: true, brand, manufacturer: null, version: m?.[1] ?? null, source: 'headers' }
}

/**
 * Identify the WAF in front of a host. SSRF-guarded (throws on an internal
 * target, like every other target-facing runner). Prefers wafw00f, falls back
 * to header detection, and degrades to a not-detected result rather than
 * throwing on any tooling problem.
 */
export async function fingerprintWaf(scheme: string, host: string, signal?: AbortSignal): Promise<WafFingerprint> {
  await assertPublicHost(host) // SSRF guard — same contract as the other runners
  const url = `${scheme}://${host}`
  try {
    // Default (first-match) mode is quicker than -a (find all); brand is what we
    // need. -o - writes the report to stdout.
    const res = await run('wafw00f', [url, '-f', 'json', '-o', '-'], { timeoutMs: 45_000, signal })
    const parsed = parseWafw00f(res.stdout)
    if (parsed) {
      parsed.version = await versionFromHeaders(url, signal)
      return parsed
    }
    // wafw00f ran but found nothing conclusive — confirm with the header check.
    return await headerFingerprint(scheme, host, signal)
  } catch (err) {
    if (err instanceof ToolNotFoundError) return headerFingerprint(scheme, host, signal)
    // Any other tooling failure (timeout, non-zero) — fall back, stay best-effort.
    return headerFingerprint(scheme, host, signal)
  }
}
