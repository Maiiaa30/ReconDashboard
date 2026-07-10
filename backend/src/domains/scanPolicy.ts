// Single gate for every ACTIVE/loud scan. Previously each route (scans, owasp,
// tool) re-implemented mode+belongs checks; this centralizes them and adds the
// authorized-engagement rails: an authorization time-window, an engagement scope
// (allow/deny hosts+CIDRs), a same-type pending guard, and a per-target cooldown.
// Passive discovery does NOT go through here.

import type { Domain } from '../db/schema'
import { getDomain } from './store'
import { hasPendingJob, lastFinishedJobAt, type JobType } from '../jobs/queue'
import { resolveDns } from '../sources/dns'
import { safeJsonParse } from '../util/json'
import { hostBelongsToDomain, isValidDomain, isValidHostname } from '../util/validate'
import { evaluateScope, parseScopeConfig, scopeIsEmpty, scopeNeedsIps } from '../util/scope'

// Modest cooldown: enough to swallow an accidental double-submit, not so long it
// blocks a deliberate re-run. Only completed jobs count (a failure retries free).
const DEFAULT_COOLDOWN_MS = 30_000

export type ScanPolicyCode =
  | 'not_found'
  | 'confirm_required'
  | 'invalid_target'
  | 'out_of_domain'
  | 'window_not_started'
  | 'window_expired'
  | 'out_of_scope'
  | 'already_pending'
  | 'cooldown'

export class ScanPolicyError extends Error {
  constructor(
    message: string,
    public status: number,
    public code: ScanPolicyCode,
    public retryAfterSec?: number,
  ) {
    super(message)
    this.name = 'ScanPolicyError'
  }
}

export interface ScanRequest {
  domainId: number
  target?: string
  confirm?: boolean
  // The active job type, used for the pending guard + cooldown key.
  jobType: JobType
  cooldownMs?: number
}

// Domain-level rails: mode gate + authorization window. Split out so a
// multi-host sweep can check them ONCE instead of per host.
export function assertDomainActive(domain: Domain, confirm?: boolean): void {
  // 1. Mode gate — passive_only needs an explicit confirm.
  if (domain.mode !== 'active_authorized' && !confirm) {
    throw new ScanPolicyError(
      `domain "${domain.host}" is passive_only — confirm you are authorized to actively scan it`,
      400,
      'confirm_required',
    )
  }
  // 2. Authorization window (active scans are time-boxed).
  const now = Date.now()
  if (domain.authorizedFrom && now < domain.authorizedFrom.getTime()) {
    throw new ScanPolicyError(
      `authorization for "${domain.host}" does not start until ${domain.authorizedFrom.toISOString()}`,
      403,
      'window_not_started',
    )
  }
  if (domain.authorizedUntil && now > domain.authorizedUntil.getTime()) {
    throw new ScanPolicyError(
      `authorization window for "${domain.host}" expired ${domain.authorizedUntil.toISOString()}`,
      403,
      'window_expired',
    )
  }
}

// Host-level rails: target validity, belongs-to-domain, engagement scope.
// Returns the normalized target. Reused per host by the sweep (which has already
// checked the domain-level rails once). Does NOT apply the pending/cooldown
// guard — those are single-scan concerns, not batch ones.
export async function assertHostInScope(domain: Domain, rawTarget?: string): Promise<string> {
  const target = (rawTarget ?? domain.host).trim().toLowerCase()
  if (target !== domain.host && !isValidHostname(target) && !isValidDomain(target)) {
    throw new ScanPolicyError(`invalid target: ${rawTarget}`, 400, 'invalid_target')
  }
  if (target !== domain.host && !hostBelongsToDomain(target, domain.host)) {
    throw new ScanPolicyError(`target ${target} is not within domain ${domain.host}`, 400, 'out_of_domain')
  }
  const scope = parseScopeConfig(safeJsonParse<unknown>(domain.scopeConfig, {}))
  if (!scopeIsEmpty(scope)) {
    let ips: string[] = []
    if (scopeNeedsIps(scope)) {
      const dns = await resolveDns(target).catch(() => null)
      ips = dns ? [...dns.a, ...dns.aaaa] : []
    }
    const res = evaluateScope(target, ips, scope)
    if (!res.inScope) {
      throw new ScanPolicyError(`target ${target} is out of scope: ${res.reason}`, 403, 'out_of_scope')
    }
  }
  return target
}

export async function assertScanAllowed(req: ScanRequest): Promise<{ domain: Domain; target: string }> {
  const domain = getDomain(req.domainId)
  if (!domain) throw new ScanPolicyError('domain not found', 404, 'not_found')

  assertDomainActive(domain, req.confirm)
  const target = await assertHostInScope(domain, req.target)

  // Don't stack a duplicate of the same active scan on the single worker.
  if (hasPendingJob(req.jobType, req.domainId)) {
    throw new ScanPolicyError(
      `a ${req.jobType} for "${domain.host}" is already queued or running`,
      409,
      'already_pending',
    )
  }

  // Per-target cooldown after a completed scan of the same type.
  const cooldownMs = req.cooldownMs ?? DEFAULT_COOLDOWN_MS
  if (cooldownMs > 0) {
    const last = lastFinishedJobAt(req.jobType, req.domainId)
    if (last && Date.now() - last.getTime() < cooldownMs) {
      const retryAfterSec = Math.ceil((cooldownMs - (Date.now() - last.getTime())) / 1000)
      throw new ScanPolicyError(
        `please wait ${retryAfterSec}s before re-running ${req.jobType} on "${domain.host}"`,
        429,
        'cooldown',
        retryAfterSec,
      )
    }
  }

  return { domain, target }
}
