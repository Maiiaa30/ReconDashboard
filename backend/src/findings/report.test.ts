import { describe, expect, it, vi } from 'vitest'

const rows: any[] = [
  { id: 1, domainId: 7, type: 'owasp', data: { category: 'A03', name: 'Confirmed injection', url: 'https://t.com/a', _scoreReasons: ['differential confirmed'] }, score: 82, severity: 'high', status: 'confirmed', note: 'Reproduced', tags: ['owasp'], createdAt: new Date(), lastSeenAt: new Date() },
  { id: 2, domainId: 7, type: 'nuclei', data: { name: 'Proof', matched: 'https://t.com/a' }, score: 95, severity: 'critical', status: 'open', note: null, tags: ['nuclei'], createdAt: new Date(), lastSeenAt: new Date() },
  { id: 3, domainId: 7, type: 'owasp', data: { name: 'Ignored noise' }, score: 99, severity: 'critical', status: 'false_positive', note: null, tags: [], createdAt: new Date(), lastSeenAt: new Date() },
]
vi.mock('../domains/store', () => ({ getDomain: () => ({ id: 7, host: 't.com', label: 'Test', mode: 'active_authorized', scopeConfig: null, authorizedFrom: null, authorizedUntil: null }) }))
vi.mock('../subdomains/store', () => ({ listSubdomains: () => [{ host: 'api.t.com', httpStatus: 200, title: 'API', server: 'nginx', ipAddress: '1.2.3.4' }] }))
vi.mock('./store', () => ({
  listFindings: () => rows,
  getFindingLinks: (id: number) => id === 1 ? [{ kind: 'confirms', direction: 'incoming', finding: rows[1] }] : [],
}))

import { buildDomainReport, buildDomainReportHtml } from './report'

describe('client engagement reports', () => {
  it('renders triage, persisted severity, evidence and finding links in Markdown', () => {
    const report = buildDomainReport(7, '2026-01-01T00:00:00.000Z')!
    expect(report).toContain('Confirmed injection')
    expect(report).toContain('differential confirmed')
    expect(report).toContain('Linked evidence')
    expect(report).toContain('confirms (incoming)')
    expect(report).not.toContain('Ignored noise')
  })

  it('renders a self-contained HTML report with linked evidence', () => {
    const html = buildDomainReportHtml(7, '2026-01-01T00:00:00.000Z')!
    expect(html).toContain('<!doctype html>')
    expect(html).toContain('Linked evidence')
    expect(html).toContain('api.t.com')
  })
})
