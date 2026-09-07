import { createHash } from 'node:crypto'
import { run } from '../util/exec'
import { BROWSER_UA } from '../util/http'
import { guardedFetchRaw } from './guard'
import { resolveDns } from './dns'
import { isInternalIp } from '../util/validate'
import { screenshotAvailable } from './screenshot'
import type { ProbeResult } from './httpProbe'

const CHROMIUM = process.env.CHROMIUM_PATH ?? 'chromium'

// A Cloudflare (and similar) JS "Just a moment…" interstitial. A plain fetch
// gets stuck here because it can't run the challenge JS; a real browser solves
// it and continues to the app, exactly like the operator's own browser does.
const CHALLENGE_RE =
  /just a moment|checking your browser|cf-browser-verification|cf_chl_opt|__cf_chl|challenge-platform|turnstile|attention required/i

function parseTitle(html: string): string | null {
  const m = html.match(/<title[^>]*>([\s\S]*?)<\/title>/i)
  return m ? m[1].replace(/\s+/g, ' ').trim().slice(0, 200) || null : null
}

/**
 * Decide whether a rendered DOM is the real application or still a bot-mitigation
 * interstitial. Exported for unit testing. A page is "cleared" when it no longer
 * carries challenge markers OR it clearly has real, substantial content.
 */
export function isChallengePage(html: string, title: string | null): boolean {
  const t = (title ?? '').toLowerCase()
  if (/just a moment|attention required|checking your browser/.test(t)) return true
  // Body markers, but only when the page is small — a real app can legitimately
  // mention "turnstile" etc. in a large bundle. The interstitial is tiny.
  if (html.length < 12_000 && CHALLENGE_RE.test(html)) return true
  return false
}

/**
 * Render a Cloudflare-challenged host through headless Chromium so the JS
 * challenge is actually solved (the plain HTTP probe only ever sees the
 * interstitial). Returns real probe data on success, or null if the browser is
 * unavailable, the host is internal/unresolvable, or the challenge did not clear.
 *
 * SSRF: identical guard to captureScreenshot — the final redirect target is
 * resolved and vetted, then Chromium is pinned to that exact address and DNS is
 * blocked for every other host so a hostile subresource can't reach the LAN.
 */
export async function browserProbeHost(host: string, signal?: AbortSignal): Promise<ProbeResult | null> {
  if (!(await screenshotAvailable())) return null
  for (const scheme of ['https', 'http'] as const) {
    if (signal?.aborted) return null
    const url = `${scheme}://${host}`
    let finalUrl: string
    let finalHost: string
    try {
      const checked = await guardedFetchRaw(url, { follow: true, timeoutMs: 9_000, maxBytes: 1024, signal })
      if (!checked) continue
      finalUrl = checked.finalUrl
      finalHost = new URL(finalUrl).hostname
      const dns = await resolveDns(finalHost)
      const ips = [...dns.a, ...dns.aaaa]
      if (!ips.length || ips.some(isInternalIp)) return null
      const { stdout } = await run(
        CHROMIUM,
        [
          '--headless=new',
          '--disable-gpu',
          '--disable-dev-shm-usage',
          '--no-sandbox',
          '--window-size=1366,768',
          // Give the challenge JS time to run and redirect to the real page.
          '--virtual-time-budget=15000',
          `--user-agent=${BROWSER_UA}`,
          `--host-resolver-rules=MAP ${finalHost} ${ips[0]}, MAP * ~NOTFOUND`,
          '--dump-dom',
          finalUrl,
        ],
        { timeoutMs: 30_000, maxBuffer: 8 * 1024 * 1024, signal },
      )
      const html = stdout ?? ''
      if (!html.trim()) continue
      const title = parseTitle(html)
      if (isChallengePage(html, title)) continue // still blocked on this scheme
      const normalized = html.replace(/\s+/g, ' ').trim()
      return {
        host,
        scheme,
        // Chromium rendered the real document, so the underlying navigation
        // succeeded — the 403/503 was only the interstitial the plain probe saw.
        status: 200,
        title,
        server: null,
        ip: ips[0] ?? null,
        url: finalUrl,
        cnames: [],
        loginHint:
          /<input[^>]+type=["']?password/i.test(html) ||
          /\b(sign[\s-]?in|log[\s-]?in)\b/i.test(title ?? ''),
        apiHint: /^api[.-]/i.test(host),
        technologies: [],
        redirect: null,
        contentHash: createHash('sha256').update(normalized).digest('hex'),
        contentLength: Buffer.byteLength(html),
        waf: 'cloudflare',
      }
    } catch {
      if (signal?.aborted) return null
      continue // try http, or give up
    }
  }
  return null
}
