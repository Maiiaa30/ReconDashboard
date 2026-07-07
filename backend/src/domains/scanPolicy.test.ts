import { describe, expect, it, vi, beforeEach } from 'vitest'
import type { Domain } from '../db/schema'

// Mock every impure dependency so the gate logic is tested in isolation.
vi.mock('./store', () => ({ getDomain: vi.fn() }))
vi.mock('../jobs/queue', () => ({ hasPendingJob: vi.fn(() => false), lastFinishedJobAt: vi.fn(() => null) }))
vi.mock('../sources/dns', () => ({ resolveDns: vi.fn(async () => ({ a: [], aaaa: [] })) }))

import { getDomain } from './store'
import { hasPendingJob, lastFinishedJobAt } from '../jobs/queue'
import { assertScanAllowed, ScanPolicyError, type ScanPolicyCode } from './scanPolicy'

const getDomainMock = vi.mocked(getDomain)
const hasPendingMock = vi.mocked(hasPendingJob)
const lastFinishedMock = vi.mocked(lastFinishedJobAt)

function domain(over: Partial<Domain> = {}): Domain {
  return {
    id: 1,
    host: 'example.com',
    label: null,
    mode: 'active_authorized',
    profile: null,
    owaspConfig: null,
    scopeConfig: null,
    authorizedFrom: null,
    authorizedUntil: null,
    monitorIntervalHours: 0,
    lastMonitoredAt: null,
    createdAt: new Date(),
    updatedAt: new Date(),
    ...over,
  } as unknown as Domain
}

const req = (over: Partial<Parameters<typeof assertScanAllowed>[0]> = {}) => ({
  domainId: 1,
  jobType: 'nmap_scan' as const,
  ...over,
})

async function expectCode(p: Promise<unknown>, code: ScanPolicyCode) {
  await expect(p).rejects.toMatchObject({ name: 'ScanPolicyError', code })
}

describe('assertScanAllowed', () => {
  beforeEach(() => {
    getDomainMock.mockReset().mockReturnValue(domain())
    hasPendingMock.mockReset().mockReturnValue(false)
    lastFinishedMock.mockReset().mockReturnValue(null)
  })

  it('rejects an unknown domain', async () => {
    getDomainMock.mockReturnValue(undefined as unknown as Domain)
    await expectCode(assertScanAllowed(req()), 'not_found')
  })

  it('requires explicit confirm on a passive_only domain', async () => {
    getDomainMock.mockReturnValue(domain({ mode: 'passive_only' }))
    await expectCode(assertScanAllowed(req()), 'confirm_required')
  })

  it('allows a passive_only domain WITH confirm', async () => {
    getDomainMock.mockReturnValue(domain({ mode: 'passive_only' }))
    const r = await assertScanAllowed(req({ confirm: true }))
    expect(r.target).toBe('example.com')
  })

  it('allows an active_authorized domain without confirm', async () => {
    const r = await assertScanAllowed(req())
    expect(r.domain.host).toBe('example.com')
  })

  it('rejects a target outside the domain', async () => {
    await expectCode(assertScanAllowed(req({ target: 'evil.com' })), 'out_of_domain')
  })

  it('accepts an in-domain subdomain target', async () => {
    const r = await assertScanAllowed(req({ target: 'api.example.com' }))
    expect(r.target).toBe('api.example.com')
  })

  it('rejects a syntactically invalid target', async () => {
    await expectCode(assertScanAllowed(req({ target: 'not a host!!' })), 'invalid_target')
  })

  it('rejects before the authorization window opens', async () => {
    getDomainMock.mockReturnValue(domain({ authorizedFrom: new Date(Date.now() + 60_000) }))
    await expectCode(assertScanAllowed(req()), 'window_not_started')
  })

  it('rejects after the authorization window expires', async () => {
    getDomainMock.mockReturnValue(domain({ authorizedUntil: new Date(Date.now() - 60_000) }))
    await expectCode(assertScanAllowed(req()), 'window_expired')
  })

  it('allows inside the authorization window', async () => {
    getDomainMock.mockReturnValue(
      domain({ authorizedFrom: new Date(Date.now() - 60_000), authorizedUntil: new Date(Date.now() + 60_000) }),
    )
    await expect(assertScanAllowed(req())).resolves.toBeTruthy()
  })

  it('enforces an allow-list scope', async () => {
    getDomainMock.mockReturnValue(domain({ scopeConfig: JSON.stringify({ allow: ['www.example.com'] }) }))
    // apex is not in the allow-list -> out of scope
    await expectCode(assertScanAllowed(req({ target: 'example.com' })), 'out_of_scope')
    // the allow-listed host passes
    const r = await assertScanAllowed(req({ target: 'www.example.com' }))
    expect(r.target).toBe('www.example.com')
  })

  it('blocks a duplicate of the same active scan', async () => {
    hasPendingMock.mockReturnValue(true)
    await expectCode(assertScanAllowed(req()), 'already_pending')
  })

  it('enforces the per-target cooldown after a recent run', async () => {
    lastFinishedMock.mockReturnValue(new Date(Date.now() - 5_000)) // 5s ago, default cooldown 30s
    await expectCode(assertScanAllowed(req()), 'cooldown')
  })

  it('allows again once the cooldown has elapsed', async () => {
    lastFinishedMock.mockReturnValue(new Date(Date.now() - 60_000))
    await expect(assertScanAllowed(req())).resolves.toBeTruthy()
  })
})

// Keep the import referenced for type-only builds.
void ScanPolicyError
