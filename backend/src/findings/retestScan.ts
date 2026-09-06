// Auto-rescan dispatcher for the retest workflow: maps a finding to the scan that
// would re-detect it and enqueues it, so "Mark for retest" re-runs the right scan
// instead of leaving the operator to launch it by hand. Re-detection then flips
// the finding back to confirmed via the addFinding upsert (see store.ts); a scan
// that does NOT re-file leaves the finding pending for the operator to verify, so
// this can never auto-mark something fixed — it is a convenience, not a verdict.

import { getDomain } from '../domains/store'
import { assertScanAllowed, ScanPolicyError } from '../domains/scanPolicy'
import { enqueueJob, type JobType } from '../jobs/queue'
import { actorName, writeAudit } from '../audit/store'
import type { getFinding } from './store'

type Finding = NonNullable<ReturnType<typeof getFinding>>

// A passive plan enqueues a domain-wide discovery directly (no active-scan gate).
// A targeted plan runs a loud scan against one host and goes through the same
// gate every manual active scan uses (mode/confirm, scope, window, cooldown).
interface RetestPlan {
  jobType: JobType
  passive: boolean
  target?: string
  params: Record<string, unknown>
  cooldownMs?: number
}

// Re-verifying a CVE runs an intrusive PoC template — keep the same long cooldown
// the manual verify path uses.
const CVE_VERIFY_COOLDOWN_MS = 6 * 60 * 60 * 1000

function str(v: unknown): string | undefined {
  return typeof v === 'string' && v.trim() ? v : undefined
}
function pathOf(url: string | null): string {
  if (!url) return '/'
  try {
    return new URL(url).pathname || '/'
  } catch {
    return '/'
  }
}
// A hostname the active gate will accept (an IP-only asset can't be scanned by name).
function scannableHost(f: Finding): string | undefined {
  const d = f.data
  const names = Array.isArray(d.hostnames) ? (d.hostnames as unknown[]).filter((h): h is string => typeof h === 'string') : []
  return names.find((h) => /[a-z]/i.test(h)) ?? (f.host && /[a-z]/i.test(f.host) ? f.host : undefined)
}

// The scan that re-detects a finding of this type, scoped to its asset, or null
// when there is no clean single-asset re-detection (leak/secret/authz/asset_change
// and the ad-hoc replay confirmers, which need the original composed request).
export function planRetestScan(f: Finding): RetestPlan | null {
  const d = f.data
  const host = f.host ?? str(d.host)
  const scheme = d.scheme === 'http' ? 'http' : 'https'
  switch (f.type) {
    // Passive, domain-wide re-discovery (no gate).
    case 'exposure':
      return { jobType: 'exposure_scan', passive: true, params: {} }
    case 'osint':
      return { jobType: 'osint_gather', passive: true, params: {} }
    case 'new_subdomain':
      return { jobType: 'subdomain_discovery', passive: true, params: {} }
    case 'api':
      return { jobType: 'api_discovery', passive: true, params: host ? { host } : {} }
    // Targeted, loud re-scans (gated).
    case 'nuclei':
      return host ? { jobType: 'nuclei_scan', passive: false, target: host, params: { scheme } } : null
    case 'owasp':
      return host ? { jobType: 'owasp_active', passive: false, target: host, params: { scheme } } : null
    case 'ffuf':
      return host ? { jobType: 'ffuf_scan', passive: false, target: host, params: { scheme, path: 'FUZZ' } } : null
    case 'nmap':
      return host ? { jobType: 'nmap_scan', passive: false, target: host, params: {} } : null
    case 'param':
      return host ? { jobType: 'param_discovery', passive: false, target: host, params: { scheme, path: pathOf(f.url) } } : null
    case 'origin': {
      const t = host ?? str(d.domain)
      return t ? { jobType: 'origin_scan', passive: false, target: t, params: {} } : null
    }
    case 'tool': {
      const tool = str(d.tool)
      return host && tool ? { jobType: 'tool_scan', passive: false, target: host, params: { tool, scheme } } : null
    }
    case 'cve_new': {
      const cveId = str(d.cveId)
      const target = scannableHost(f)
      return cveId && target
        ? { jobType: 'cve_verify', passive: false, target, params: { cveId, ip: f.ip ?? undefined, kev: d.kev === true, scheme }, cooldownMs: CVE_VERIFY_COOLDOWN_MS }
        : null
    }
    default:
      return null
  }
}

export type RetestRescan =
  | { kind: 'none' } // no clean re-detection for this finding type
  | { kind: 'queued'; jobId: number; jobType: JobType }
  | { kind: 'blocked'; jobType: JobType; code: string; message: string; retryAfterSec?: number }

// Enqueue the re-detection scan for a finding (already moved to retest_pending by
// the caller). Targeted scans go through assertScanAllowed so the passive-domain
// confirm gate, scope, window and cooldown all apply exactly as for a manual scan;
// a blocked scan is reported back (not thrown) so the finding stays pending.
export async function runRetestScan(f: Finding, opts: { confirm?: boolean; userId?: number }): Promise<RetestRescan> {
  if (f.domainId == null) return { kind: 'none' }
  const plan = planRetestScan(f)
  if (!plan) return { kind: 'none' }

  try {
    let target: string | undefined
    if (plan.passive) {
      if (!getDomain(f.domainId)) return { kind: 'none' }
    } else {
      const res = await assertScanAllowed({ domainId: f.domainId, target: plan.target, confirm: opts.confirm, jobType: plan.jobType, cooldownMs: plan.cooldownMs })
      target = res.target
    }
    const params = { domainId: f.domainId, ...(target ? { target } : {}), ...plan.params }
    const jobId = enqueueJob(plan.jobType, params)
    const domain = getDomain(f.domainId)
    writeAudit({
      actor: actorName(opts.userId),
      action: `enqueue:${plan.jobType}`,
      domainId: f.domainId,
      target: target ?? null,
      mode: domain?.mode ?? null,
      jobId,
      detail: { retestOf: f.id },
    })
    return { kind: 'queued', jobId, jobType: plan.jobType }
  } catch (err) {
    if (err instanceof ScanPolicyError) {
      return { kind: 'blocked', jobType: plan.jobType, code: err.code, message: err.message, retryAfterSec: err.retryAfterSec }
    }
    throw err
  }
}
