import { describe, expect, it } from 'vitest'
import { validate, ContractError } from './http'
import {
  findingSchema, jobSchema, subdomainPageSchema,
  captureSchema, domainSchema, domainOverviewSchema, auditEntrySchema,
  metaStatusSchema, correlateResponseSchema, checkHostResultSchema, sitemapResponseSchema, nextActionSchema,
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

  it('accepts intel, checkhost, sitemap and meta shapes', () => {
    const correlate = { paths: [], signatureClusters: [] }
    expect(validate(correlateResponseSchema, correlate, '/correlate').paths).toEqual([])

    const na = {
      key: 'k', priority: 1, risk: 'high', mode: 'loud', automation: 'guided', source: 'finding',
      title: 't', why: 'w', target: 'x', page: 'findings', moduleLabel: 'Findings', status: 'open', findingIds: [],
    }
    expect(validate(nextActionSchema, na, '/next').risk).toBe('high')
    expect(() => validate(nextActionSchema, { ...na, mode: 'bogus' }, '/next')).toThrow(ContractError)

    const check = {
      target: 'a.com', resolvedIp: '1.2.3.4',
      dns: { a: ['1.2.3.4'], aaaa: [], cname: [], ns: [] },
      ping: { available: true, alive: true, transmitted: 1, received: 1, lossPct: 0, rttMs: { min: 1, avg: 1, max: 1 }, error: null },
      tcp: [{ port: 443, open: true, latencyMs: 5 }], http: null,
    }
    expect(validate(checkHostResultSchema, check, '/check').tcp[0].port).toBe(443)

    const sitemap = { hosts: [{ host: 'a.com', count: 1, endpoints: [{ path: '/', method: 'GET', status: 200, source: 'captured', url: 'https://a.com/' }] }] }
    expect(validate(sitemapResponseSchema, sitemap, '/sitemap').hosts[0].endpoints[0].source).toBe('captured')

    const meta = {
      scorer: 'rules', aiProvider: 'none', scheduler: { enabled: true, intervalMinutes: 60 }, discordConfigured: false,
      tools: { subfinder: true, nmap: true, nuclei: true, ffuf: true, chromium: true, dig: true },
      wordlists: [],
      readiness: {
        checkedAt: 1, database: { ok: true, sizeBytes: 1 }, storage: { freeBytes: null },
        worker: { running: true, startedAt: null, lastTickAt: null, lanes: { passive: true, loud: true } },
        queue: { queued: 0, running: 0, failed: 0, lastActivityAt: null },
        capture: { enabled: false, extensionSeenAt: null }, backup: { serverPassphraseConfigured: false },
      },
    }
    expect(validate(metaStatusSchema, meta, '/meta').tools.nmap).toBe(true)
  })
})
