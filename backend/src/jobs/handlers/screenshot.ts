import { getDomain } from '../../domains/store'
import { captureScreenshot, screenshotAvailable } from '../../sources/screenshot'
import { listSubdomains, updateScreenshot } from '../../subdomains/store'
import { mapLimit } from '../../util/async'
import { screenshotPathFor } from '../../util/screenshotPaths'
import { isInternalIp } from '../../util/validate'
import { createHash } from 'node:crypto'
import { readFile } from 'node:fs/promises'
import { alertChanges, recordAndDetectChanges } from '../../findings/changeWatch'
import type { JobContext } from '../worker'

// Keep worst-case wall-clock (ceil(MAX_SHOTS/CONCURRENCY) * per-shot timeout)
// comfortably under the worker's per-job timeout.
const MAX_SHOTS = 60
const CONCURRENCY = 3

async function fileHash(path: string): Promise<string | null> {
  try { return createHash('sha256').update(await readFile(path)).digest('hex') } catch { return null }
}

// Screenshot the live web hosts of a domain (those that responded to the probe).
export async function screenshotHandler({ params, log, signal, progress }: JobContext) {
  const domainId = Number(params.domainId)
  const domain = getDomain(domainId)
  if (!domain) throw new Error(`domain ${domainId} not found`)

  if (!(await screenshotAvailable())) {
    return { available: false, note: 'chromium not installed in this image' }
  }

  // Only screenshot hosts that responded to HTTP/HTTPS during discovery.
  const live = listSubdomains(domainId)
    .filter((s) => s.httpStatus != null && s.scheme && !(s.ipAddress && isInternalIp(s.ipAddress)))
    .slice(0, MAX_SHOTS)

  if (live.length === 0) {
    return { available: true, captured: 0, note: 'no live web hosts to screenshot (run discovery first)' }
  }

  let captured = 0
  await mapLimit(
    live,
    CONCURRENCY,
    async (s) => {
      if (signal.aborted) return false
      const url = `${s.scheme}://${s.host}`
      const out = screenshotPathFor(domainId, s.host)
      const previousHash = await fileHash(out)
      progress(`capturing ${s.host}`)
      const ok = await captureScreenshot(url, out, signal)
      if (ok) {
        updateScreenshot(domainId, s.host, out)
        const screenshotHash = await fileHash(out)
        if (screenshotHash) {
          const changes = recordAndDetectChanges(domainId, `host:${s.host}`, { screenshotHash })
          // A pre-existing image with no DB baseline is baselined silently. Once
          // a baseline exists, a changed PNG becomes a material timeline event.
          if (previousHash && changes.length) await alertChanges(domainId, `host:${s.host}`, [s.host], changes)
        }
        captured++
      }
      return ok
    },
    false,
  )

  log.info({ domain: domain.host, captured, of: live.length }, 'screenshots captured')
  return { available: true, captured, attempted: live.length }
}
