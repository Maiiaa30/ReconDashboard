import { beforeEach, describe, expect, it, vi } from 'vitest'

const due: any[] = []
const domains: any[] = []
vi.mock('../config', () => ({ config: { leaks: { enabled: true }, githubToken: 'configured' } }))
vi.mock('../domains/store', () => ({
  domainsDueForMonitoring: () => due,
  listDomains: () => domains,
  markMonitored: vi.fn(),
}))
vi.mock('./queue', () => ({
  enqueueJob: vi.fn(),
  hasPendingJob: vi.fn(() => false),
  lastJobAt: vi.fn(() => null),
}))

import { markMonitored } from '../domains/store'
import { enqueueJob, hasPendingJob } from './queue'
import { runSchedulerTick } from './scheduler'

const log = { info: vi.fn(), error: vi.fn() } as any

describe('runSchedulerTick', () => {
  beforeEach(() => {
    due.length = 0
    domains.length = 0
    vi.mocked(enqueueJob).mockReset()
    vi.mocked(hasPendingJob).mockReset().mockReturnValue(false)
    vi.mocked(markMonitored).mockReset()
  })

  it('enqueues only passive monitoring jobs and stamps the domain', () => {
    due.push({ id: 7, host: 't.com', monitorIntervalHours: 6 })
    runSchedulerTick(log, 1_000_000)
    expect(vi.mocked(enqueueJob).mock.calls.map((call) => call[0])).toEqual([
      'subdomain_discovery', 'exposure_scan', 'osint_gather', 'api_discovery',
    ])
    expect(markMonitored).toHaveBeenCalledWith(7)
  })

  it('deduplicates pending jobs and isolates a failing domain', () => {
    due.push({ id: 1, host: 'bad.test', monitorIntervalHours: 1 }, { id: 2, host: 'good.test', monitorIntervalHours: 1 })
    vi.mocked(hasPendingJob).mockImplementation((type, id) => id === 2 && type === 'osint_gather')
    vi.mocked(enqueueJob).mockImplementation((type, params: any) => {
      if (params.domainId === 1 && type === 'exposure_scan') throw new Error('queue unavailable')
      return 1
    })
    runSchedulerTick(log, 1_000_000)
    expect(markMonitored).toHaveBeenCalledWith(2)
    expect(markMonitored).not.toHaveBeenCalledWith(1)
    expect(vi.mocked(enqueueJob).mock.calls.some(([type, params]: any[]) => type === 'api_discovery' && params.domainId === 2)).toBe(true)
  })

  it('schedules daily leak sources only for authorized domains', () => {
    domains.push({ id: 3, host: 'active.test', mode: 'active_authorized' }, { id: 4, host: 'passive.test', mode: 'passive_only' })
    runSchedulerTick(log, 2_000_000)
    const calls = vi.mocked(enqueueJob).mock.calls
    expect(calls).toContainEqual(['leak_check', { domainId: 3 }])
    expect(calls).toContainEqual(['code_leak', { domainId: 3 }])
    expect(calls.some(([, p]: any[]) => p.domainId === 4)).toBe(false)
  })
})
