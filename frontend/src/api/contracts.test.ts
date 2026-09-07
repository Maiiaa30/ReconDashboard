import { describe, expect, it } from 'vitest'
import { validate, ContractError } from './http'
import {
  findingSchema, jobSchema, subdomainPageSchema,
  captureSchema, domainSchema, domainOverviewSchema, auditEntrySchema,
} from './schemas'

const finding = {
  id: 1, domainId: 2, type: 'owasp', data: { foo: 'bar' }, score: 90,
  severity: 'high', host: 'a.com', ip: null, url: null, jobId: null,
  tags: ['x'], status: 'open', note: null, createdAt: 't', lastSeenAt: null,
  retestRequestedAt: null,
}

describe('response contracts', () => {
  it('accepts a well-formed object', () => {
    expect(validate(findingSchema, finding, '/findings').id).toBe(1)
  })

  it('tolerates unknown extra fields (backend added a column)', () => {
    const out = validate(findingSchema, { ...finding, brandNewField: 42 }, '/findings')
    expect(out.id).toBe(1)
  })

  it('throws ContractError on a missing required field', () => {
    const { score, ...missing } = finding
    void score
    expect(() => validate(findingSchema, missing, '/findings')).toThrow(ContractError)
  })

  it('throws ContractError on a wrong-typed field', () => {
    expect(() => validate(jobSchema, { ...finding, id: 'not-a-number' }, '/jobs')).toThrow(ContractError)
  })

  it('validates nested page shapes', () => {
    const page = { subdomains: [], nextCursor: null }
    expect(validate(subdomainPageSchema, page, '/subs').nextCursor).toBeNull()
    expect(() => validate(subdomainPageSchema, { subdomains: [{ id: 'x' }], nextCursor: null }, '/subs')).toThrow(ContractError)
  })

  it('accepts capture, domain, overview and audit shapes', () => {
    const capture = {
      id: 1, domainId: null, method: 'GET', url: 'https://a.com/', host: 'a.com',
      headers: [['accept', '*/*']], body: null, source: 'ext', createdAt: 't',
    }
    expect(validate(captureSchema, capture, '/capture').method).toBe('GET')

    const domain = { id: 1, host: 'a.com', label: null, mode: 'passive_only', createdAt: 't', updatedAt: 't' }
    expect(validate(domainSchema, domain, '/domains').mode).toBe('passive_only')
    expect(() => validate(domainSchema, { ...domain, mode: 'nonsense' }, '/domains')).toThrow(ContractError)

    const overview = {
      id: 1, host: 'a.com', label: null, mode: 'active_authorized', createdAt: 1,
      subdomains: { total: 0, new: 0 }, findings: { total: 0, maxScore: null },
      exposure: { ips: 0, openPorts: 0, cves: 0 }, lastActivity: null, monitorIntervalHours: 24,
    }
    expect(validate(domainOverviewSchema, overview, '/overview').monitorIntervalHours).toBe(24)

    const audit = { id: 1, ts: 't', actor: 'op', action: 'scan', domainId: null, target: null, mode: null, jobId: null, detail: null }
    expect(validate(auditEntrySchema, audit, '/audit').action).toBe('scan')
  })
})
