import { describe, expect, it } from 'vitest'
import { validate, ContractError } from './http'
import { findingSchema, jobSchema, subdomainPageSchema } from './schemas'

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
})
