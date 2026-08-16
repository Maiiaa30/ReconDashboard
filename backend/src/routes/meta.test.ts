import { describe, expect, it } from 'vitest'
import { getLocalReadiness } from './meta'

describe('local readiness', () => {
  it('reports database, storage, worker, queue, capture and backup state', () => {
    const readiness = getLocalReadiness()

    expect(readiness.database.ok).toBe(true)
    expect(readiness.database.sizeBytes).toBeGreaterThan(0)
    expect(readiness.storage.freeBytes).toEqual(expect.any(Number))
    expect(readiness.worker.running).toBe(false)
    expect(readiness.queue).toMatchObject({
      queued: expect.any(Number),
      running: expect.any(Number),
      failed: expect.any(Number),
    })
    expect(readiness.capture).toHaveProperty('enabled')
    expect(readiness.backup).toHaveProperty('serverPassphraseConfigured')
  })
})
