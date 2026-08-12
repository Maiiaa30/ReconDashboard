import { beforeEach, describe, expect, it, vi } from 'vitest'

const { queued, queueMocks } = vi.hoisted(() => {
  const queued: Record<'passive' | 'loud', any[]> = { passive: [], loud: [] }
  return {
    queued,
    queueMocks: {
      claimNextQueued: vi.fn((lane: 'passive' | 'loud') => queued[lane].shift()),
      failJob: vi.fn(), finishJob: vi.fn(), markJobCancelled: vi.fn(), setJobProgress: vi.fn(),
      isLoudJob: vi.fn((type: string) => type === 'nmap_scan'),
    },
  }
})
vi.mock('./queue', () => ({
  JOB_TIMEOUT_MS: 20_000,
  ...queueMocks,
  reapTimedOutRunning: vi.fn(() => ({ dead: 0, requeued: 0, cancelled: 0 })),
  requeueStaleRunning: vi.fn(() => ({ requeued: 0, dead: 0, cancelled: 0 })),
}))
vi.mock('../audit/store', () => ({ writeAudit: vi.fn() }))
vi.mock('./chains', () => ({ chainAfter: vi.fn() }))
vi.mock('./jobContext', () => ({ runInJobContext: (_id: number, fn: () => unknown) => fn() }))

import { chainAfter } from './chains'
import { cancelRunningJob, registerHandler, runClaimedJob, tickLane } from './worker'

const log = { info: vi.fn(), warn: vi.fn(), error: vi.fn() } as any
const job = (id: number, type: string, domainId = 1) => ({ id, type, domainId, status: 'running', params: JSON.stringify({ domainId }), attempts: 1, cancelRequested: false }) as any

describe('worker orchestration', () => {
  beforeEach(() => {
    queued.passive.length = 0
    queued.loud.length = 0
    Object.values(queueMocks).forEach((mock) => mock.mockClear())
    vi.mocked(chainAfter).mockClear()
  })

  it('runs passive and loud lanes concurrently while each lane stays sequential', async () => {
    queued.passive.push(job(1, 'subdomain_discovery'))
    queued.loud.push(job(2, 'nmap_scan'))
    const started: string[] = []
    let release!: () => void
    const gate = new Promise<void>((resolve) => { release = resolve })
    registerHandler('subdomain_discovery', async () => { started.push('passive'); await gate; return {} })
    registerHandler('nmap_scan', async () => { started.push('loud'); await gate; return {} })
    const running = Promise.all([tickLane('passive', log), tickLane('loud', log)])
    await vi.waitFor(() => expect(started.sort()).toEqual(['loud', 'passive']))
    release()
    await running
    expect(queueMocks.finishJob).toHaveBeenCalledTimes(2)
  })

  it('cancels an in-flight handler and does not dispatch a completion chain', async () => {
    registerHandler('nmap_scan', async ({ signal }) => new Promise((_resolve, reject) => signal.addEventListener('abort', () => reject(new Error('aborted')), { once: true })))
    const running = runClaimedJob(job(9, 'nmap_scan'), log)
    await vi.waitFor(() => expect(cancelRunningJob(9)).toBe(true))
    await running
    expect(queueMocks.markJobCancelled).toHaveBeenCalledWith(9)
    expect(chainAfter).not.toHaveBeenCalled()
  })

  it('dispatches chainAfter only after a successful job', async () => {
    registerHandler('subdomain_discovery', async () => ({ newCount: 1 }))
    const j = job(12, 'subdomain_discovery')
    await runClaimedJob(j, log)
    expect(chainAfter).toHaveBeenCalledWith(j, { newCount: 1 }, log)
  })
})
