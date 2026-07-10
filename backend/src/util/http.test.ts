import { describe, it, expect } from 'vitest'
import { withHostLimit } from './http'

describe('withHostLimit', () => {
  it('never exceeds the per-host concurrency limit and completes all tasks', async () => {
    let active = 0
    let peak = 0
    let done = 0
    const run = () =>
      withHostLimit('https://provider.example/api', async () => {
        active++
        peak = Math.max(peak, active)
        await new Promise((r) => setTimeout(r, 5))
        active--
        done++
      })
    await Promise.all(Array.from({ length: 25 }, run))
    expect(peak).toBeLessThanOrEqual(4) // PER_HOST_LIMIT
    expect(active).toBe(0)
    expect(done).toBe(25)
  })

  it('runs distinct hosts in parallel (limit is per-host, not global)', async () => {
    let active = 0
    let peak = 0
    const run = (host: string) =>
      withHostLimit(`https://${host}/`, async () => {
        active++
        peak = Math.max(peak, active)
        await new Promise((r) => setTimeout(r, 5))
        active--
      })
    await Promise.all(Array.from({ length: 8 }, (_, i) => run(`h${i}.example`)))
    expect(peak).toBeGreaterThan(4) // 8 different hosts aren't throttled against each other
  })

  it('releases the slot even when the task throws', async () => {
    const boom = () =>
      withHostLimit('https://err.example/', async () => {
        throw new Error('nope')
      })
    await Promise.allSettled(Array.from({ length: 10 }, boom))
    // If a throw leaked a slot, this follow-up would hang; a timeout guards us.
    let ran = false
    await withHostLimit('https://err.example/', async () => {
      ran = true
    })
    expect(ran).toBe(true)
  })
})
