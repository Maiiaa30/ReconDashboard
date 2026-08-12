// The ONE canonical mapping from a finding's numeric score to a severity bucket.
// Previously the report (low = score < 40) and the snapshot summary (low = 20-39)
// disagreed, so the same finding was bucketed differently in the report vs its
// headline counts. Everything now derives severity from here so they agree, and
// the bucket is stored on the finding row for indexed filtering + correlation.

export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info'

export function severityBucket(score: number | null | undefined): Severity {
  const s = score ?? 0
  if (s >= 90) return 'critical'
  if (s >= 70) return 'high'
  if (s >= 40) return 'medium'
  if (s >= 20) return 'low'
  return 'info'
}

// Report/snapshot group critical + high together under "high".
export function isHigh(sev: Severity): boolean {
  return sev === 'critical' || sev === 'high'
}

// Prefer the persisted severity column. The score fallback keeps pre-migration
// rows readable until they are refreshed by a scan.
export function findingSeverity(finding: { severity?: string | null; score?: number | null }): Severity {
  const stored = finding.severity
  if (stored === 'critical' || stored === 'high' || stored === 'medium' || stored === 'low' || stored === 'info') return stored
  return severityBucket(finding.score)
}
