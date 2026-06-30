import { dirname, join, resolve } from 'node:path'
import { config } from '../config'

// Screenshots live next to the DB (the mounted /data volume in Docker).
// Kept dependency-free so both the job handler and the domain store can use it.
export const SCREENSHOT_DIR = join(dirname(resolve(config.databasePath)), 'screenshots')

export function sanitizeHostForFile(host: string): string {
  return host.toLowerCase().replace(/[^a-z0-9._-]/g, '_').slice(0, 200)
}

export function screenshotPathFor(domainId: number, host: string): string {
  return join(SCREENSHOT_DIR, String(domainId), `${sanitizeHostForFile(host)}.png`)
}

export function screenshotDirFor(domainId: number): string {
  return join(SCREENSHOT_DIR, String(domainId))
}
