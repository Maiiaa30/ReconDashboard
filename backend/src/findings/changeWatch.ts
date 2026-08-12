import { and, eq } from 'drizzle-orm'
import { db } from '../db/index'
import { assetSnapshots } from '../db/schema'
import { addFinding } from './store'
import { alertList, isDiscordConfigured } from '../notify/discord'
import { safeJsonParse } from '../util/json'

// A suggested, gated follow-up the operator can one-click from the change finding.
export interface SuggestedAction {
  kind: 'nmap' | 'owasp'
  label: string
  target: string
}

// Per-asset attribute change watch — generalizes the cveWatch baseline pattern.
// On each exposure scan we snapshot an IP's open ports / tech / up-ness, diff it
// against the stored baseline, and emit a `changed_*` finding (+ Discord alert)
// on a MATERIAL change. Detection only: the finding carries a suggested gated
// action, but nothing loud is ever enqueued here (operator-gated execution).

export interface AssetSnapshot {
  ports?: number[]
  tech?: string[]
  up?: boolean
  title?: string | null
  certFp?: string | null
  status?: number | null
  server?: string | null
  redirect?: string | null
  contentHash?: string | null
  contentLength?: number | null
  screenshotHash?: string | null
}

export type AssetChange =
  | { kind: 'new_port'; port: number }
  | { kind: 'new_tech'; tech: string }
  | { kind: 'up' }
  | { kind: 'down' }
  | { kind: 'title_changed'; from: string; to: string }
  | { kind: 'cert_changed'; from: string; to: string }
  | { kind: 'status_changed'; from: number; to: number }
  | { kind: 'server_changed'; from: string; to: string }
  | { kind: 'redirect_changed'; from: string; to: string }
  | { kind: 'content_changed'; fromLength: number | null; toLength: number | null }
  | { kind: 'screenshot_changed' }

// PURE: material differences from the previous snapshot to the current one.
export function diffSnapshot(prev: AssetSnapshot, cur: AssetSnapshot): AssetChange[] {
  const out: AssetChange[] = []
  const prevPorts = new Set(prev.ports ?? [])
  for (const p of cur.ports ?? []) if (!prevPorts.has(p)) out.push({ kind: 'new_port', port: p })
  const prevTech = new Set((prev.tech ?? []).map((t) => t.toLowerCase()))
  for (const t of cur.tech ?? []) if (!prevTech.has(t.toLowerCase())) out.push({ kind: 'new_tech', tech: t })
  if (cur.up && !prev.up) out.push({ kind: 'up' })
  if (cur.up === false && prev.up) out.push({ kind: 'down' })
  if (prev.title && cur.title && prev.title !== cur.title) out.push({ kind: 'title_changed', from: prev.title, to: cur.title })
  if (prev.certFp && cur.certFp && prev.certFp !== cur.certFp) out.push({ kind: 'cert_changed', from: prev.certFp, to: cur.certFp })
  if (prev.status != null && cur.status != null && prev.status !== cur.status) out.push({ kind: 'status_changed', from: prev.status, to: cur.status })
  if (prev.server && cur.server && prev.server !== cur.server) out.push({ kind: 'server_changed', from: prev.server, to: cur.server })
  if (prev.redirect && cur.redirect && prev.redirect !== cur.redirect) out.push({ kind: 'redirect_changed', from: prev.redirect, to: cur.redirect })
  if (prev.contentHash && cur.contentHash && prev.contentHash !== cur.contentHash) {
    const fromLength = prev.contentLength ?? null
    const toLength = cur.contentLength ?? null
    const delta = fromLength != null && toLength != null ? Math.abs(toLength - fromLength) : null
    const threshold = fromLength != null ? Math.max(64, Math.round(fromLength * 0.05)) : 0
    if (delta == null || delta >= threshold) out.push({ kind: 'content_changed', fromLength, toLength })
  }
  if (prev.screenshotHash && cur.screenshotHash && prev.screenshotHash !== cur.screenshotHash) out.push({ kind: 'screenshot_changed' })
  return out
}

// Record the current snapshot for an IP and return the material changes vs the
// stored baseline. The first-ever snapshot only baselines (returns []), so the
// initial discovery of an asset never floods the operator with "changes".
export function recordAndDetectChanges(domainId: number, ip: string, cur: AssetSnapshot): AssetChange[] {
  const prevRow = db
    .select()
    .from(assetSnapshots)
    .where(and(eq(assetSnapshots.domainId, domainId), eq(assetSnapshots.ip, ip)))
    .limit(1)
    .all()[0]
  const prev: AssetSnapshot | null = prevRow ? {
    ports: safeJsonParse<number[]>(prevRow.ports, []),
    tech: safeJsonParse<string[]>(prevRow.tech, []),
    up: !!prevRow.up,
    title: prevRow.title,
    certFp: prevRow.certFp,
    status: prevRow.status,
    server: prevRow.server,
    redirect: prevRow.redirect,
    contentHash: prevRow.contentHash,
    contentLength: prevRow.contentLength,
    screenshotHash: prevRow.screenshotHash,
  } : null
  const merged: Required<Pick<AssetSnapshot, 'ports' | 'tech' | 'up'>> & AssetSnapshot = {
    ports: cur.ports ?? prev?.ports ?? [],
    tech: cur.tech ?? prev?.tech ?? [],
    up: cur.up ?? prev?.up ?? false,
    title: cur.title !== undefined ? cur.title : prev?.title ?? null,
    certFp: cur.certFp !== undefined ? cur.certFp : prev?.certFp ?? null,
    status: cur.status !== undefined ? cur.status : prev?.status ?? null,
    server: cur.server !== undefined ? cur.server : prev?.server ?? null,
    redirect: cur.redirect !== undefined ? cur.redirect : prev?.redirect ?? null,
    contentHash: cur.contentHash !== undefined ? cur.contentHash : prev?.contentHash ?? null,
    contentLength: cur.contentLength !== undefined ? cur.contentLength : prev?.contentLength ?? null,
    screenshotHash: cur.screenshotHash !== undefined ? cur.screenshotHash : prev?.screenshotHash ?? null,
  }
  const values = {
    ports: JSON.stringify(merged.ports), tech: JSON.stringify(merged.tech), up: merged.up,
    title: merged.title ?? null, certFp: merged.certFp ?? null, status: merged.status ?? null,
    server: merged.server ?? null, redirect: merged.redirect ?? null, contentHash: merged.contentHash ?? null,
    contentLength: merged.contentLength ?? null, screenshotHash: merged.screenshotHash ?? null, updatedAt: new Date(),
  }

  if (!prevRow) {
    db.insert(assetSnapshots).values({ domainId, ip, ...values }).onConflictDoNothing().run()
    return []
  }
  const changes = diffSnapshot(prev!, merged)
  db.update(assetSnapshots).set(values).where(and(eq(assetSnapshots.domainId, domainId), eq(assetSnapshots.ip, ip))).run()
  return changes
}

// Map a change to its finding fields + a suggested (gated) follow-up action.
function describe(change: AssetChange, ip: string, host: string): { title: string; detail: string; score: number; action?: SuggestedAction } {
  switch (change.kind) {
    case 'new_port':
      return {
        title: `New open port on ${host} (${ip}): ${change.port}`,
        detail: `Port ${change.port} is newly open on ${ip} — a fresh service to enumerate`,
        score: 55,
        action: { kind: 'nmap', label: `Scan ${ip} ports/services`, target: ip },
      }
    case 'new_tech':
      return {
        title: `New tech on ${host} (${ip}): ${change.tech}`,
        detail: `${change.tech} is newly detected on ${ip} — re-run active checks for its known issues`,
        score: 45,
        action: { kind: 'owasp', label: `OWASP checks on ${host}`, target: host },
      }
    case 'up':
      return { title: `${host} (${ip}) is newly reachable`, detail: `${ip} now exposes open ports — it was previously dark`, score: 40, action: { kind: 'owasp', label: `OWASP checks on ${host}`, target: host } }
    case 'down':
      return { title: `${host} (${ip}) went dark`, detail: `${ip} no longer exposes open ports`, score: 25 }
    case 'title_changed':
      return { title: `Page title changed on ${host}`, detail: `Title changed from "${change.from}" to "${change.to}"`, score: 30, action: { kind: 'owasp', label: `Review ${host}`, target: host } }
    case 'cert_changed':
      return { title: `TLS certificate changed on ${host}`, detail: `Certificate fingerprint changed from ${change.from} to ${change.to}`, score: 40, action: { kind: 'owasp', label: `Review ${host}`, target: host } }
    case 'status_changed':
      return { title: `HTTP status changed on ${host}`, detail: `Response changed from HTTP ${change.from} to HTTP ${change.to}`, score: 30, action: { kind: 'owasp', label: `Review ${host}`, target: host } }
    case 'server_changed':
      return { title: `Web server changed on ${host}`, detail: `Server changed from "${change.from}" to "${change.to}"`, score: 35, action: { kind: 'owasp', label: `Review ${host}`, target: host } }
    case 'redirect_changed':
      return { title: `Redirect changed on ${host}`, detail: `Redirect target changed from "${change.from}" to "${change.to}"`, score: 35, action: { kind: 'owasp', label: `Review ${host}`, target: host } }
    case 'content_changed':
      return { title: `Response content changed on ${host}`, detail: `Material response change detected${change.fromLength != null && change.toLength != null ? ` (${change.fromLength} to ${change.toLength} bytes)` : ''}`, score: 25, action: { kind: 'owasp', label: `Review ${host}`, target: host } }
    case 'screenshot_changed':
      return { title: `Visual appearance changed on ${host}`, detail: 'The latest screenshot differs from the previous baseline', score: 25, action: { kind: 'owasp', label: `Review ${host}`, target: host } }
  }
}

// Persist one `asset_change` finding per change (deduped by ip:kind:detail) and
// fire a single grouped Discord alert. The finding carries a gated one-click
// action; NOTHING loud is enqueued here.
export async function alertChanges(domainId: number, ip: string, hostnames: string[], changes: AssetChange[]): Promise<void> {
  if (!changes.length) return
  const host = hostnames[0] ?? ip
  for (const c of changes) {
    const { title, detail, score, action } = describe(c, ip, host)
    addFinding({
      domainId,
      type: 'asset_change',
      data: { ip, host, hostnames, change: c.kind, detail, title, action, _scoreReasons: [detail, 'detected by the change watch — review and, if warranted, run the suggested scan'] },
      score,
      tags: ['asset-change', `change:${c.kind}`],
    })
  }
  if (isDiscordConfigured()) {
    try {
      await alertList(`🛰️ ${changes.length} change(s) on ${host} (${ip})`, changes.map((c) => describe(c, ip, host).title))
    } catch {
      /* best-effort */
    }
  }
}
