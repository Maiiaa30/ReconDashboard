import { describe, expect, it } from 'vitest'
import { booleanConfirmed, timingConfirmed } from './injection'

const body = (n: number) => 'x'.repeat(n)

describe('booleanConfirmed', () => {
  it('confirms when true≈baseline and false diverges', () => {
    // baseline 1000, AND 1=1 → 1000 (normal page), AND 1=2 → 50 (empty result)
    expect(booleanConfirmed(body(1000), body(1000), body(50))).toBe(true)
  })

  it('does NOT confirm a reflection-only endpoint (both branches identical)', () => {
    // The page just echoes the payload → true and false responses look the same.
    expect(booleanConfirmed(body(1000), body(1000), body(1000))).toBe(false)
  })

  it('does NOT confirm when the true-branch does not match the baseline', () => {
    expect(booleanConfirmed(body(1000), body(300), body(50))).toBe(false)
  })
})

describe('timingConfirmed', () => {
  it('confirms an injected SLEEP(5) — sleep times ~5s above baseline', () => {
    const base = [180, 210, 195, 205]
    const sleep = [5210, 5180, 5230, 5195]
    expect(timingConfirmed(base, sleep, 5)).toBe(true)
  })

  it('is robust to a single slow baseline blip (median ignores it)', () => {
    const base = [190, 200, 4000, 195] // one blip
    const sleep = [5200, 5180, 5220, 5210]
    expect(timingConfirmed(base, sleep, 5)).toBe(true)
  })

  it('does NOT confirm when only one sleep response was slow (median stays low)', () => {
    const base = [190, 200, 195, 205]
    const sleep = [210, 205, 9000, 200] // a single outlier, median ~207
    expect(timingConfirmed(base, sleep, 5)).toBe(false)
  })

  it('does NOT confirm when there is no meaningful delay', () => {
    expect(timingConfirmed([200, 210, 190], [230, 220, 240], 5)).toBe(false)
  })

  it('requires at least 2 samples each', () => {
    expect(timingConfirmed([200], [5200], 5)).toBe(false)
  })
})
