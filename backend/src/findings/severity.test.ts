import { describe, expect, it } from 'vitest'
import { isHigh, severityBucket } from './severity'

// Both the engagement report and its snapshot summary bucket findings through
// severityBucket, so they can no longer disagree (the old bug: report low = score
// < 40, snapshot low = 20-39). This locks the boundaries down.
describe('severityBucket', () => {
  it('maps scores to the canonical buckets at the boundaries', () => {
    expect(severityBucket(90)).toBe('critical')
    expect(severityBucket(89)).toBe('high')
    expect(severityBucket(70)).toBe('high')
    expect(severityBucket(69)).toBe('medium')
    expect(severityBucket(40)).toBe('medium')
    expect(severityBucket(39)).toBe('low')
    expect(severityBucket(20)).toBe('low')
    expect(severityBucket(19)).toBe('info')
    expect(severityBucket(0)).toBe('info')
  })

  it('treats null/undefined score as info', () => {
    expect(severityBucket(null)).toBe('info')
    expect(severityBucket(undefined)).toBe('info')
  })

  it('info-level (score < 20) falls outside high/medium/low in BOTH report and snapshot', () => {
    // The fix: a score-10 finding is neither low nor higher, so report.low and
    // snapshot.low agree (both exclude it) instead of report counting it.
    const b = severityBucket(10)
    expect(b).toBe('info')
    expect(['high', 'medium', 'low']).not.toContain(b)
  })
})

describe('isHigh', () => {
  it('groups critical + high together', () => {
    expect(isHigh('critical')).toBe(true)
    expect(isHigh('high')).toBe(true)
    expect(isHigh('medium')).toBe(false)
    expect(isHigh('low')).toBe(false)
    expect(isHigh('info')).toBe(false)
  })
})
