import { afterEach, describe, expect, it, vi } from 'vitest'
import { api } from './api'

function jsonResponse(body: unknown): Response {
  return {
    ok: true,
    status: 200,
    text: async () => JSON.stringify(body),
  } as Response
}

describe('API request lifecycle', () => {
  afterEach(() => vi.unstubAllGlobals())

  it('passes the polling AbortSignal to fetch', async () => {
    const fetchMock = vi.fn().mockResolvedValue(jsonResponse({ jobs: [] }))
    vi.stubGlobal('fetch', fetchMock)
    const controller = new AbortController()

    await api.jobs({ signal: controller.signal })

    expect(fetchMock).toHaveBeenCalledWith('/api/jobs', expect.objectContaining({ signal: controller.signal }))
  })

  it('keeps query construction intact when a signal is supplied', async () => {
    const fetchMock = vi.fn().mockResolvedValue(jsonResponse({ findings: [] }))
    vi.stubGlobal('fetch', fetchMock)
    const controller = new AbortController()

    await api.findings({ domainId: 9, type: 'nuclei', limit: 25 }, { signal: controller.signal })

    expect(fetchMock).toHaveBeenCalledWith(
      '/api/findings?domainId=9&type=nuclei&limit=25',
      expect.objectContaining({ signal: controller.signal }),
    )
  })

  it('serializes every findings facet plus the pagination cursor', async () => {
    const fetchMock = vi.fn().mockResolvedValue(jsonResponse({ findings: [], nextCursor: null }))
    vi.stubGlobal('fetch', fetchMock)

    await api.findings({
      domainId: 3,
      type: 'owasp',
      status: 'active',
      severity: 'high',
      asset: 'a.example.com',
      tag: 'kev',
      since: 1000,
      limit: 50,
      cursor: 'abc',
    })

    expect(fetchMock).toHaveBeenCalledWith(
      '/api/findings?domainId=3&type=owasp&asset=a.example.com&tag=kev&since=1000&status=active&severity=high&limit=50&cursor=abc',
      expect.anything(),
    )
  })

  it('summary omits the status/severity facets and pagination', async () => {
    const fetchMock = vi.fn().mockResolvedValue(jsonResponse({ total: 0, byStatus: {}, bySeverity: {} }))
    vi.stubGlobal('fetch', fetchMock)

    await api.findingsSummary({ domainId: 3, type: 'owasp', asset: 'a', tag: 'kev', since: 1000 })

    expect(fetchMock).toHaveBeenCalledWith(
      '/api/findings/summary?domainId=3&type=owasp&asset=a&tag=kev&since=1000',
      expect.anything(),
    )
  })

  it('serializes every audit facet plus the pagination cursor', async () => {
    const fetchMock = vi.fn().mockResolvedValue(jsonResponse({ entries: [], nextCursor: null }))
    vi.stubGlobal('fetch', fetchMock)

    await api.audit({
      domainId: 7,
      actor: 'maia',
      action: 'job:done',
      mode: 'active',
      target: 'a.example.com',
      since: 1000,
      limit: 50,
      cursor: '42',
    })

    expect(fetchMock).toHaveBeenCalledWith(
      '/api/audit?domainId=7&actor=maia&mode=active&target=a.example.com&since=1000&action=job%3Adone&limit=50&cursor=42',
      expect.anything(),
    )
  })

  it('audit summary omits the action facet and pagination', async () => {
    const fetchMock = vi.fn().mockResolvedValue(jsonResponse({ total: 0, byAction: {} }))
    vi.stubGlobal('fetch', fetchMock)

    await api.auditSummary({ domainId: 7, actor: 'maia', mode: 'active', target: 'a', since: 1000 })

    expect(fetchMock).toHaveBeenCalledWith(
      '/api/audit/summary?domainId=7&actor=maia&mode=active&target=a&since=1000',
      expect.anything(),
    )
  })

  it('serializes every subdomains-page facet plus the pagination cursor', async () => {
    const fetchMock = vi.fn().mockResolvedValue(jsonResponse({ subdomains: [], nextCursor: null }))
    vi.stubGlobal('fetch', fetchMock)

    await api.subdomainsPage(7, { q: 'api', newOnly: true, sort: 'host', dir: 'asc', limit: 50, cursor: 'abc' })

    expect(fetchMock).toHaveBeenCalledWith(
      '/api/domains/7/subdomains/page?q=api&newOnly=1&sort=host&dir=asc&limit=50&cursor=abc',
      expect.anything(),
    )
  })

  it('subdomains summary carries only the host filter', async () => {
    const fetchMock = vi.fn().mockResolvedValue(jsonResponse({ total: 0, newCount: 0 }))
    vi.stubGlobal('fetch', fetchMock)

    await api.subdomainsSummary(7, { q: 'api' })

    expect(fetchMock).toHaveBeenCalledWith('/api/domains/7/subdomains/summary?q=api', expect.anything())
  })
})
