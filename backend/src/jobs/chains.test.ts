import { beforeEach, describe, expect, it, vi } from 'vitest'

// chains.ts only touches the queue; mock it so we can assert what gets enqueued
// without a DB. hasPendingJob defaults to "nothing pending" so chains fire.
vi.mock('./queue', () => ({ enqueueJob: vi.fn(), hasPendingJob: vi.fn(() => false) }))

import { enqueueJob, hasPendingJob } from './queue'
import { chainAfter } from './chains'
import type { Job } from '../db/schema'

const mockEnqueue = vi.mocked(enqueueJob)
const mockPending = vi.mocked(hasPendingJob)
const log = { info: vi.fn(), warn: vi.fn() } as any
const job = (over: Partial<Job>): Job => ({ id: 1, type: 'exposure_scan', domainId: 7, status: 'done', params: '{}', ...over } as Job)

const enqueuedTypes = () => mockEnqueue.mock.calls.map((c) => c[0])

// Nothing loud may ever be auto-chained (safety invariant #3).
const LOUD = ['nmap_scan', 'nuclei_scan', 'ffuf_scan', 'owasp_active', 'tool_scan', 'origin_scan', 'intruder', 'cve_verify', 'authz_diff', 'param_discovery']

describe('chainAfter', () => {
  beforeEach(() => {
    mockEnqueue.mockReset()
    mockPending.mockReset()
    mockPending.mockReturnValue(false)
  })

  it('refreshes osint + api_discovery after an exposure scan', () => {
    chainAfter({ ...job({}), type: 'exposure_scan', domainId: 7 } as Job, null, log)
    expect(enqueuedTypes()).toEqual(expect.arrayContaining(['osint_gather', 'api_discovery']))
  })

  it('enqueues exposure (and screenshots when new hosts) after discovery', () => {
    chainAfter({ ...job({}), type: 'subdomain_discovery', domainId: 7 } as Job, { newCount: 3 }, log)
    expect(enqueuedTypes()).toEqual(expect.arrayContaining(['exposure_scan', 'screenshot']))
  })

  it('does not enqueue screenshots when discovery found nothing new', () => {
    chainAfter({ ...job({}), type: 'subdomain_discovery', domainId: 7 } as Job, { newCount: 0 }, log)
    expect(enqueuedTypes()).toContain('exposure_scan')
    expect(enqueuedTypes()).not.toContain('screenshot')
  })

  it('dedupes via hasPendingJob (enqueues nothing when already pending)', () => {
    mockPending.mockReturnValue(true)
    chainAfter({ ...job({}), type: 'exposure_scan', domainId: 7 } as Job, null, log)
    expect(mockEnqueue).not.toHaveBeenCalled()
  })

  it('never auto-chains a LOUD job type', () => {
    chainAfter({ ...job({}), type: 'subdomain_discovery', domainId: 7 } as Job, { newCount: 5 }, log)
    chainAfter({ ...job({}), type: 'exposure_scan', domainId: 7 } as Job, null, log)
    for (const t of enqueuedTypes()) expect(LOUD).not.toContain(t)
  })

  it('does nothing for a domainless job', () => {
    chainAfter({ ...job({}), type: 'exposure_scan', domainId: null } as Job, null, log)
    expect(mockEnqueue).not.toHaveBeenCalled()
  })
})
