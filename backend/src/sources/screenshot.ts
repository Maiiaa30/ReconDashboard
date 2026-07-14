import { mkdir, stat } from 'node:fs/promises'
import { dirname } from 'node:path'
import { run, toolExists } from '../util/exec'
import { BROWSER_UA } from '../util/http'

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
export async function captureScreenshot(url: string, outPath: string): Promise<boolean> {
  try {
    await mkdir(dirname(outPath), { recursive: true })
    await run(
      CHROMIUM,
      [
        '--headless=new',
        '--no-sandbox',
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
        `--screenshot=${outPath}`,
        url,
      ],
      { timeoutMs: 45_000 },
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
