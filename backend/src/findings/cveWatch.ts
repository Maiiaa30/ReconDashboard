import { and, eq, inArray, isNull, ne } from 'drizzle-orm'
import { db } from '../db/index'
import { assetCves } from '../db/schema'
import { addFinding } from './store'
import { alertList, isDiscordConfigured } from '../notify/discord'

// "New CVE on a known asset" watch. On every exposure ingest we record the CVE
// set seen on an (domain, ip) and surface the ones that are genuinely NEW since
// the asset was baselined — a fresh critical exposure on something we already
// track. The FIRST scan of an asset only baselines (no alert on initial
// discovery, or you'd get 33 alerts the first time you scan a host).

export interface AssetCve {
  id: string
  cvss: number | null
  kev: boolean
}

// Sentinel row recording that an asset has been scanned at least once, even when
// that scan found zero CVEs. Without it, a host that is CLEAN at first scan
// leaves no rows, so its later first CVE looks like a brand-new baseline and
// never alerts — exactly the transition this watch exists to catch.
const BASELINE_MARKER = '__baseline__'

// Record the current CVE set for an asset and return the CVEs that still need an
// alert. Crash-safety (audit §3 #5): a CVE row is written with alerted_at = NULL
// and only stamped once its alert has actually fired (markCvesAlerted). So this
// returns EVERY un-alerted CVE for the asset — the ones new this run PLUS any left
// un-alerted by a prior run that crashed between recording and alerting — instead
// of "CVEs never seen before". Baseline rows (the asset's first-ever scan) are
// written already-alerted so the initial discovery never alerts.
export function recordAndDetectNewCves(domainId: number, ip: string, cves: AssetCve[]): AssetCve[] {
  const known = new Set(
    db
      .select({ cveId: assetCves.cveId })
      .from(assetCves)
      .where(and(eq(assetCves.domainId, domainId), eq(assetCves.ip, ip)))
      .all()
      .map((r) => r.cveId),
  )
  // Seen before iff any row exists (a CVE row OR the baseline marker).
  const seenBefore = known.size > 0

  const now = new Date()
  // Drop a baseline marker on the first scan so a future clean→CVE transition is
  // detectable even if this scan (and the first) found nothing. Markers never
  // alert, so they are stamped immediately.
  if (!known.has(BASELINE_MARKER)) {
    db.insert(assetCves)
      .values({ domainId, ip, cveId: BASELINE_MARKER, cvss: null, kev: false, firstSeenAt: now, alertedAt: now })
      .onConflictDoNothing()
      .run()
  }

  for (const c of cves) {
    if (known.has(c.id)) continue
    known.add(c.id)
    db.insert(assetCves)
      .values({
        domainId,
        ip,
        cveId: c.id,
        cvss: c.cvss,
        kev: c.kev,
        firstSeenAt: now,
        // First-ever scan = baseline: stamp it so it never alerts. A later scan
        // = genuinely new: leave alerted_at NULL so it is alerted (and re-driven
        // if we crash before the alert fires).
        alertedAt: seenBefore ? null : now,
      })
      .onConflictDoNothing()
      .run()
  }

  // Everything un-alerted for this asset (excluding the marker) is due an alert.
  return db
    .select({ cveId: assetCves.cveId, cvss: assetCves.cvss, kev: assetCves.kev })
    .from(assetCves)
    .where(
      and(
        eq(assetCves.domainId, domainId),
        eq(assetCves.ip, ip),
        isNull(assetCves.alertedAt),
        ne(assetCves.cveId, BASELINE_MARKER),
      ),
    )
    .all()
    .map((r) => ({ id: r.cveId, cvss: r.cvss, kev: r.kev }))
}

// Stamp CVE rows as alerted — called by the handler ONLY after alertNewCves has
// finished, so an interruption before this point leaves them re-drivable.
export function markCvesAlerted(domainId: number, ip: string, cveIds: string[]): void {
  if (!cveIds.length) return
  db.update(assetCves)
    .set({ alertedAt: new Date() })
    .where(and(eq(assetCves.domainId, domainId), eq(assetCves.ip, ip), inArray(assetCves.cveId, cveIds)))
    .run()
}

function scoreFor(c: AssetCve): number {
  if (c.kev) return 100
  if (c.cvss != null) return Math.max(1, Math.min(100, Math.round(c.cvss * 10)))
  return 75 // unknown severity but newly appeared — still noteworthy
}

// Persist one critical finding per new CVE (deduped by cvenew:ip:cveId) and fire
// a single grouped Discord alert. Idempotent-friendly: re-scans update the same
// finding rows, and the Discord alert only fires for CVEs flagged new this run.
export async function alertNewCves(
  domainId: number,
  ip: string,
  hostnames: string[],
  fresh: AssetCve[],
): Promise<void> {
  if (!fresh.length) return
  const host = hostnames[0] ?? ip

  for (const c of fresh) {
    const reasons = [
      `New CVE ${c.id} appeared on already-tracked asset ${host} (${ip})`,
      c.kev ? 'On CISA KEV — known exploited in the wild' : c.cvss != null ? `CVSS ${c.cvss}` : 'severity unknown',
    ]
    addFinding({
      domainId,
      type: 'cve_new',
      data: { ip, host, hostnames, cveId: c.id, cvss: c.cvss, kev: c.kev, _scoreReasons: reasons },
      score: scoreFor(c),
      tags: [
        'cve-new',
        `cve:${c.id}`,
        ...(c.kev ? ['kev'] : []),
        ...(c.cvss != null && c.cvss >= 9 ? ['cvss:critical'] : []),
      ],
    })
  }

  // The durable cve_new findings above are the primary alert; Discord is a
  // best-effort notification. Swallow its failures so a webhook outage doesn't
  // throw (which would stop the handler from marking these CVEs alerted and make
  // them re-fire every scan). The finding is already persisted.
  if (isDiscordConfigured()) {
    try {
      await alertList(
        `🚨 ${fresh.length} new CVE(s) on ${host} (${ip})`,
        fresh.map((c) => `${c.id}${c.kev ? ' [KEV]' : ''}${c.cvss != null ? ` · CVSS ${c.cvss}` : ''}`),
      )
    } catch {
      /* notification is best-effort */
    }
  }
}
