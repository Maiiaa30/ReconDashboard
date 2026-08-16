import { afterEach, describe, expect, it, vi } from 'vitest'
import { riskFromScore, summarizeFinding, timeAgo } from './format'

describe('format helpers', () => {
  afterEach(() => vi.useRealTimers())

  it('uses stable risk thresholds', () => {
    expect(riskFromScore(null)).toBe('none')
    expect(riskFromScore(19)).toBe('none')
    expect(riskFromScore(20)).toBe('low')
    expect(riskFromScore(40)).toBe('medium')
    expect(riskFromScore(70)).toBe('high')
  })

  it('formats recent timestamps without negative durations', () => {
    vi.useFakeTimers()
    vi.setSystemTime(new Date('2026-08-16T12:00:00Z'))

    expect(timeAgo(Date.parse('2026-08-16T11:55:00Z'))).toBe('5m ago')
    expect(timeAgo(Date.parse('2026-08-16T12:05:00Z'))).toBe('just now')
    expect(timeAgo(null)).toBe('never')
  })

  it('never exposes a leaked plaintext password in a finding summary', () => {
    const summary = summarizeFinding('leak', {
      email: 'operator@example.test',
      source: 'breach-source',
      password: 'do-not-render-this',
    })

    expect(summary).toContain('password exposed')
    expect(summary).not.toContain('do-not-render-this')
  })
})
