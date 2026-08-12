import { mkdir, mkdtemp, readFile, rm, stat, writeFile } from 'node:fs/promises'
import { dirname, join } from 'node:path'
import { tmpdir } from 'node:os'
import { pathToFileURL } from 'node:url'
import { run, toolExists } from '../util/exec'
import { BROWSER_UA } from '../util/http'
import { guardedFetchRaw } from './guard'
import { resolveDns } from './dns'
import { isInternalIp } from '../util/validate'

const CHROMIUM = process.env.CHROMIUM_PATH ?? 'chromium'

let availabilityChecked = false
let available = false

export async function screenshotAvailable(): Promise<boolean> {
  if (!availabilityChecked) {
    available = await toolExists(CHROMIUM)
    availabilityChecked = true
  }
  return available
}

// Capture a full-window PNG of `url` to `outPath` using headless Chromium.
// Returns true if a non-empty image was written. Never throws.
export async function captureScreenshot(url: string, outPath: string, signal?: AbortSignal): Promise<boolean> {
  try {
    // Resolve and guard the final redirect target immediately before Chromium,
    // then pin that hostname to the vetted address for the browser connection.
    const checked = await guardedFetchRaw(url, { follow: true, timeoutMs: 9_000, maxBytes: 1024, signal })
    if (!checked) return false
    const finalUrl = checked.finalUrl
    const finalHost = new URL(finalUrl).hostname
    const dns = await resolveDns(finalHost)
    const ips = [...dns.a, ...dns.aaaa]
    if (!ips.length || ips.some(isInternalIp)) return false
    await mkdir(dirname(outPath), { recursive: true })
    await run(
      CHROMIUM,
      [
        '--headless=new',
        '--disable-gpu',
        '--disable-dev-shm-usage',
        '--hide-scrollbars',
        '--force-color-profile=srgb',
        '--window-size=1366,768',
        '--virtual-time-budget=12000',
        // Match the HTTP probe's browser UA — WAF-fronted hosts (Cloudflare
        // "Just a moment…") serve a challenge page to a headless/bot UA, which
        // produces a useless screenshot.
        `--user-agent=${BROWSER_UA}`,
        // Keep the page on the vetted address and block DNS for every other
        // hostname so hostile subresources cannot turn Chromium into an SSRF
        // client for services on the local network.
        `--host-resolver-rules=MAP ${finalHost} ${ips[0]}, MAP * ~NOTFOUND`,
        `--screenshot=${outPath}`,
        finalUrl,
      ],
      { timeoutMs: 45_000, signal },
    )
  } catch {
    // chromium can exit non-zero but still write the file; fall through to check.
  }
  try {
    const s = await stat(outPath)
    return s.size > 0
  } catch {
    return false
  }
}

// Render a self-contained HTML string to a PDF buffer via headless Chromium's
// print-to-PDF (reuses the same binary as screenshots). Returns null if Chromium
// is unavailable or produced nothing. Never throws.
export async function renderHtmlToPdf(html: string): Promise<Buffer | null> {
  if (!(await screenshotAvailable())) return null
  const dir = await mkdtemp(join(tmpdir(), 'recon-pdf-'))
  const htmlPath = join(dir, 'report.html')
  const pdfPath = join(dir, 'report.pdf')
  try {
    await writeFile(htmlPath, html, 'utf8')
    try {
      await run(
        CHROMIUM,
        [
          '--headless=new',
          '--disable-gpu',
          '--disable-dev-shm-usage',
          '--no-pdf-header-footer',
          `--print-to-pdf=${pdfPath}`,
          pathToFileURL(htmlPath).toString(),
        ],
        { timeoutMs: 45_000 },
      )
    } catch {
      // Chromium can exit non-zero but still write the file; check below.
    }
    const s = await stat(pdfPath)
    return s.size > 0 ? await readFile(pdfPath) : null
  } catch {
    return null
  } finally {
    await rm(dir, { recursive: true, force: true }).catch(() => {})
  }
}
