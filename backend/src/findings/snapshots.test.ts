import { describe, expect, it, vi } from 'vitest'

vi.mock('../db/index', () => ({ db: {} }))
vi.mock('../domains/store', () => ({ getDomain: vi.fn() }))
vi.mock('./store', () => ({ listFindings: vi.fn() }))
vi.mock('./report', () => ({ buildDomainReport: vi.fn(), buildDomainReportHtml: vi.fn() }))

import { summariseFindingRows } from './snapshots'

describe('snapshot summary', () => {
  it('uses persisted severity and excludes false-positive/ignored findings', () => {
    const meta = summariseFindingRows([
      { type: 'owasp', score: 5, severity: 'critical', status: 'open', data: {}, tags: [] },
      { type: 'owasp', score: 99, severity: 'low', status: 'open', data: {}, tags: [] },
      { type: 'exposure', score: 50, severity: 'medium', status: 'open', data: { vulns: ['A', 'B'] }, tags: [] },
      { type: 'owasp', score: 99, severity: 'critical', status: 'false_positive', data: {}, tags: [] },
    ] as any)
    expect(meta).toEqual({ findings: 3, high: 1, medium: 1, low: 1, cves: 2 })
  })
})
