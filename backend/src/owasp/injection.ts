// Boolean- and time-based blind-injection CONFIRMATION — pure, so the differential
// logic is unit-testable without a network. You already ship SQLi/cmdi payloads;
// this proves them. Both confirmers are deliberately conservative (a false positive
// on "RCE-confirmed" is worse than a miss) and robust to network jitter.

function median(xs: number[]): number {
  if (xs.length === 0) return 0
  const s = [...xs].sort((a, b) => a - b)
  const mid = Math.floor(s.length / 2)
  return s.length % 2 ? s[mid] : (s[mid - 1] + s[mid]) / 2
}

// Two bodies are "the same" when their lengths are within 5% — same rendered page,
// allowing small per-request variance (csrf tokens, timestamps).
function lenSimilar(a: string, b: string): boolean {
  const m = Math.max(a.length, b.length, 1)
  return Math.abs(a.length - b.length) / m <= 0.05
}

// Boolean-based: a TRUE condition (…AND 1=1) renders like the baseline, a FALSE
// condition (…AND 1=2) diverges. Confirmed when the two conditions differ from
// EACH OTHER and the true-branch matches the baseline — that rules out a page that
// simply reflects the payload (both branches would then look identical).
export function booleanConfirmed(baseBody: string, trueBody: string, falseBody: string): boolean {
  return !lenSimilar(trueBody, falseBody) && lenSimilar(baseBody, trueBody)
}

// Time-based: N baseline request times vs N sleep-payload times (ms), for an
// injected SLEEP(k). Confirmed when the median sleep time exceeds the median
// baseline by roughly k seconds — medians ignore a single slow blip, and the
// delta must sit in a band around k (not just "one response was slow"). Requires
// at least 2 samples each.
export function timingConfirmed(baseTimes: number[], sleepTimes: number[], kSeconds: number): boolean {
  if (baseTimes.length < 2 || sleepTimes.length < 2 || kSeconds <= 0) return false
  const kMs = kSeconds * 1000
  const baseMed = median(baseTimes)
  const sleepMed = median(sleepTimes)
  const delta = sleepMed - baseMed
  // delta ≈ k (network shaves a bit, so allow 0.6k; cap at 3k so one pathological
  // outlier can't confirm), and the sleep median must be clearly above baseline.
  return delta >= 0.6 * kMs && delta <= 3 * kMs && sleepMed > baseMed * 1.5
}
