import { createDecipheriv, pbkdf2Sync } from 'node:crypto'
import { mkdtemp, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import Database from 'better-sqlite3'
import { run } from '../util/exec'
import { BROWSER_UA } from '../util/http'
import { guardedFetchRaw } from './guard'
import { resolveDns } from './dns'
import { detectWaf } from './httpProbe'
import { isInternalIp, normalizeHost } from '../util/validate'
import { screenshotAvailable } from './screenshot'

// Cloudflare-clearance harvester. A plain HTTP client is stuck at the "Just a
// moment…" JS challenge, so ACTIVE scans (nuclei/ffuf/the OWASP engine) that hit
// a Cloudflare-fronted host get 403/503 on every request. This module drives the
// same headless Chromium the screenshot path uses to SOLVE the challenge once,
// then lifts the resulting cf_clearance / __cf_bm cookies out of the browser
// profile so those cookies (with the matching browser UA) can be replayed on the
// scan's own requests — exactly what a browser session would send.
//
// Reliability caveat: Cloudflare often binds cf_clearance to the client IP + UA;
// it is replayed with the same UA from the same host, which works for the common
// JS-challenge configuration but not against a strict TLS-fingerprint binding.
// Every failure path returns null and the scan simply proceeds unauthenticated.

const CHROMIUM = process.env.CHROMIUM_PATH ?? 'chromium'

export interface Clearance {
  cookie: string // "cf_clearance=…; __cf_bm=…"
  userAgent: string
}

// cf_clearance lives ~30 min; cache a little under that so a multi-step scan
// reuses one solve instead of launching a browser per request.
const TTL_MS = 20 * 60_000
const cache = new Map<string, { value: Clearance | null; exp: number }>()

// Linux headless Chromium with no desktop keyring encrypts cookies with a fixed
// key ("peanuts"/"saltysalt", 1 PBKDF2 round) and a v10 tag — deterministic and
// documented. A keyring-backed profile uses v11 (a real OS secret) which we
// can't read; that just yields null. IV is 16 spaces; AES-128-CBC.
const KEY = pbkdf2Sync('peanuts', 'saltysalt', 1, 16, 'sha1')
const IV = Buffer.alloc(16, ' ')

/**
 * Decrypt one Chromium `encrypted_value` blob. Returns null unless it is a
 * v10 (no-keyring) cookie that decrypts to a clean ASCII token. Exported for
 * unit testing. Chrome M124+ prepends a 32-byte SHA-256 domain hash to the
 * plaintext; that prefix is stripped when present.
 */
export function decryptCookieValue(encrypted: Buffer): string | null {
  if (encrypted.length < 3 || encrypted.subarray(0, 3).toString() !== 'v10') return null
  try {
    const decipher = createDecipheriv('aes-128-cbc', KEY, IV)
    let out = Buffer.concat([decipher.update(encrypted.subarray(3)), decipher.final()])
    // Strip the 32-byte domain-hash prefix present in newer Chrome builds — it is
    // binary, so its presence is detectable by a non-printable leading byte.
    if (out.length > 32 && out[0] < 0x20) out = out.subarray(32)
    const value = out.toString('utf8')
    return /^[\x20-\x7e]+$/.test(value) ? value : null
  } catch {
    return null
  }
}

/** Build the cookie header from a profile's Cookies DB. Exported for testing. */
export function readClearanceCookies(dbPath: string, host: string): string | null {
  let db: Database.Database | null = null
  try {
    db = new Database(dbPath, { readonly: true, fileMustExist: true })
    const rows = db
      .prepare('SELECT name, host_key, encrypted_value FROM cookies WHERE name IN (?, ?)')
      .all('cf_clearance', '__cf_bm') as { name: string; host_key: string; encrypted_value: Buffer }[]
    const parts: string[] = []
    for (const name of ['cf_clearance', '__cf_bm']) {
      const row = rows.find((r) => {
        if (r.name !== name) return false
        const key = r.host_key.replace(/^\./, '')
        return host === key || host.endsWith(`.${key}`) || key.endsWith(`.${host}`)
      })
      if (!row) continue
      const value = decryptCookieValue(row.encrypted_value)
      if (value) parts.push(`${name}=${value}`)
    }
    // cf_clearance is the one that actually clears the challenge; __cf_bm alone is
    // not enough, so require it.
    return parts.some((p) => p.startsWith('cf_clearance=')) ? parts.join('; ') : null
  } catch {
    return null
  } finally {
    db?.close()
  }
}

async function solve(host: string, signal?: AbortSignal): Promise<Clearance | null> {
  if (!(await screenshotAvailable())) return null
  const userDataDir = await mkdtemp(join(tmpdir(), 'recon-cf-'))
  try {
    for (const scheme of ['https', 'http'] as const) {
      if (signal?.aborted) return null
      try {
        const checked = await guardedFetchRaw(`${scheme}://${host}`, { follow: true, timeoutMs: 9_000, maxBytes: 1024, signal })
        if (!checked) continue
        const finalUrl = checked.finalUrl
        const finalHost = new URL(finalUrl).hostname
        const dns = await resolveDns(finalHost)
        const ips = [...dns.a, ...dns.aaaa]
        if (!ips.length || ips.some(isInternalIp)) return null
        // Solve the challenge in a persistent profile so the cookies are flushed
        // to disk; SSRF-pinned exactly like captureScreenshot/browserProbe.
        await run(
          CHROMIUM,
          [
            '--headless=new',
            '--disable-gpu',
            '--disable-dev-shm-usage',
            '--no-sandbox',
            `--user-data-dir=${userDataDir}`,
            '--virtual-time-budget=15000',
            `--user-agent=${BROWSER_UA}`,
            `--host-resolver-rules=MAP ${finalHost} ${ips[0]}, MAP * ~NOTFOUND`,
            '--dump-dom',
            finalUrl,
          ],
          { timeoutMs: 30_000, maxBuffer: 8 * 1024 * 1024, signal },
        )
        const cookie = readClearanceCookies(join(userDataDir, 'Default', 'Cookies'), finalHost)
        if (cookie) return { cookie, userAgent: BROWSER_UA }
      } catch {
        if (signal?.aborted) return null
        continue
      }
    }
    return null
  } finally {
    await rm(userDataDir, { recursive: true, force: true }).catch(() => {})
  }
}

/**
 * Get a cached (or freshly solved) Cloudflare clearance for a host, or null if
 * the host isn't challenged, Chromium is unavailable, or the solve failed.
 * Concurrency-safe enough for the scan lanes: a stale/missing entry re-solves.
 */
export async function getClearance(rawHost: string, signal?: AbortSignal): Promise<Clearance | null> {
  const host = normalizeHost(rawHost)
  if (!host) return null
  const hit = cache.get(host)
  if (hit && hit.exp > Date.now()) return hit.value
  const value = await solve(host, signal)
  cache.set(host, { value, exp: Date.now() + TTL_MS })
  return value
}

/**
 * Header map ({ Cookie, User-Agent }) to merge into a target request so it rides
 * the solved Cloudflare clearance, or {} when there's nothing to add. Merge with
 * any existing auth header the operator configured.
 */
export async function clearanceHeaders(host: string, signal?: AbortSignal): Promise<Record<string, string>> {
  const c = await getClearance(host, signal).catch(() => null)
  return c ? { Cookie: c.cookie, 'User-Agent': c.userAgent } : {}
}

/**
 * Cheap check: does the host answer its root request with a Cloudflare challenge
 * (403/503 behind Cloudflare)? Used to gate the expensive browser solve so a
 * scan only launches Chromium for hosts that are actually blocked.
 */
async function isCloudflareChallenged(host: string, signal?: AbortSignal): Promise<boolean> {
  for (const scheme of ['https', 'http'] as const) {
    const res = await guardedFetchRaw(`${scheme}://${host}`, { follow: true, timeoutMs: 8_000, maxBytes: 64 * 1024, signal }).catch(() => null)
    if (!res) continue
    if ((res.status === 403 || res.status === 503) && detectWaf(res.headers, res.body) === 'cloudflare') return true
    return false // reachable but not challenged
  }
  return false
}

/**
 * Header CLI args (`-H "Cookie: …" -H "User-Agent: …"`) to pass to an external
 * scanner (nuclei/ffuf — both take repeatable `-H`) so it rides a solved
 * Cloudflare clearance. Empty when the target isn't challenged or the solve
 * failed, so the scan proceeds exactly as before.
 */
export async function clearanceCliArgs(rawHost: string, signal?: AbortSignal): Promise<string[]> {
  const c = await getClearanceIfChallenged(rawHost, signal)
  return c ? ['-H', `Cookie: ${c.cookie}`, '-H', `User-Agent: ${c.userAgent}`] : []
}

/**
 * sqlmap-style clearance args (`--cookie=… --user-agent=…`) — sqlmap does not
 * take `-H`. Empty when the target isn't challenged or the solve failed.
 */
export async function clearanceCookieArgs(rawHost: string, signal?: AbortSignal): Promise<string[]> {
  const c = await getClearanceIfChallenged(rawHost, signal)
  return c ? [`--cookie=${c.cookie}`, `--user-agent=${c.userAgent}`] : []
}

/**
 * Header map ({ Cookie, User-Agent }) for an in-process guardedFetch caller, but
 * ONLY when the host is actually Cloudflare-challenged (so a browser isn't
 * launched for every host). Empty otherwise. Unlike clearanceHeaders(), this
 * gates on a challenge check itself — use it in tool routines that fire many
 * requests and don't pre-detect the challenge.
 */
export async function clearanceHeadersIfChallenged(rawHost: string, signal?: AbortSignal): Promise<Record<string, string>> {
  const c = await getClearanceIfChallenged(rawHost, signal)
  return c ? { Cookie: c.cookie, 'User-Agent': c.userAgent } : {}
}

/** Solve clearance only if the host is actually Cloudflare-challenged. */
export async function getClearanceIfChallenged(rawHost: string, signal?: AbortSignal): Promise<Clearance | null> {
  const host = normalizeHost(rawHost)
  if (!host) return null
  if (!(await isCloudflareChallenged(host, signal).catch(() => false))) return null
  return getClearance(host, signal).catch(() => null)
}

/** Test-only: reset the in-memory clearance cache. */
export function _resetClearanceCache(): void {
  cache.clear()
}
