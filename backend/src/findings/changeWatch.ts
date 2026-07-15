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
  ports: number[]
  tech: string[]
  up: boolean
}

export type AssetChange =
  | { kind: 'new_port'; port: number }
  | { kind: 'new_tech'; tech: string }
  | { kind: 'up' }
  | { kind: 'down' }

// PURE: material differences from the previous snapshot to the current one.
export function diffSnapshot(prev: AssetSnapshot, cur: AssetSnapshot): AssetChange[] {
  const out: AssetChange[] = []
  const prevPorts = new Set(prev.ports)
  for (const p of cur.ports) if (!prevPorts.has(p)) out.push({ kind: 'new_port', port: p })
  const prevTech = new Set(prev.tech.map((t) => t.toLowerCase()))
  for (const t of cur.tech) if (!prevTech.has(t.toLowerCase())) out.push({ kind: 'new_tech', tech: t })
  if (cur.up && !prev.up) out.push({ kind: 'up' })
  if (!cur.up && prev.up) out.push({ kind: 'down' })
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
  const values = { ports: JSON.stringify(cur.ports), tech: JSON.stringify(cur.tech), up: cur.up, updatedAt: new Date() }

  if (!prevRow) {
    db.insert(assetSnapshots).values({ domainId, ip, ...values }).onConflictDoNothing().run()
    return []
  }
  const prev: AssetSnapshot = {
    ports: safeJsonParse<number[]>(prevRow.ports, []),
    tech: safeJsonParse<string[]>(prevRow.tech, []),
    up: !!prevRow.up,
  }
  const changes = diffSnapshot(prev, cur)
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
