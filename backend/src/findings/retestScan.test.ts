import { describe, expect, it, vi } from 'vitest'

// planRetestScan is pure (reads only the finding), so stub the DB handle that the
// module's transitive imports open at load time.
vi.mock('../db/index', () => ({ db: {} }))

import { planRetestScan } from './retestScan'

// Minimal finding matching the fields planRetestScan reads.
function f(partial: { type: string; domainId?: number | null; host?: string | null; ip?: string | null; url?: string | null; data?: Record<string, unknown> }) {
  return {
    id: 1,
    domainId: partial.domainId ?? 7,
    host: partial.host ?? null,
    ip: partial.ip ?? null,
    url: partial.url ?? null,
    type: partial.type,
    data: partial.data ?? {},
  } as unknown as Parameters<typeof planRetestScan>[0]
}

describe('planRetestScan', () => {
  it('maps passive domain-wide types to their discovery job (no target)', () => {
    expect(planRetestScan(f({ type: 'exposure' }))).toMatchObject({ jobType: 'exposure_scan', passive: true })
    expect(planRetestScan(f({ type: 'osint' }))).toMatchObject({ jobType: 'osint_gather', passive: true })
    expect(planRetestScan(f({ type: 'new_subdomain', host: 'a.example.com' }))).toMatchObject({ jobType: 'subdomain_discovery', passive: true })
    expect(planRetestScan(f({ type: 'api', host: 'api.example.com' }))).toMatchObject({ jobType: 'api_discovery', passive: true, params: { host: 'api.example.com' } })
  })

  it('maps targeted loud types to a gated scan scoped to the host', () => {
    expect(planRetestScan(f({ type: 'nuclei', host: 'a.example.com', data: { scheme: 'http' } }))).toMatchObject({
      jobType: 'nuclei_scan',
      passive: false,
      target: 'a.example.com',
      params: { scheme: 'http' },
    })
    expect(planRetestScan(f({ type: 'owasp', host: 'a.example.com' }))).toMatchObject({ jobType: 'owasp_active', target: 'a.example.com', params: { scheme: 'https' } })
    expect(planRetestScan(f({ type: 'ffuf', host: 'a.example.com' }))).toMatchObject({ jobType: 'ffuf_scan', target: 'a.example.com', params: { scheme: 'https', path: 'FUZZ' } })
    expect(planRetestScan(f({ type: 'nmap', host: 'a.example.com' }))).toMatchObject({ jobType: 'nmap_scan', target: 'a.example.com' })
    expect(planRetestScan(f({ type: 'tool', host: 'a.example.com', data: { tool: 'sslscan' } }))).toMatchObject({ jobType: 'tool_scan', target: 'a.example.com', params: { tool: 'sslscan', scheme: 'https' } })
  })

  it('derives the param-discovery path from the finding url', () => {
    expect(planRetestScan(f({ type: 'param', host: 'a.example.com', url: 'https://a.example.com/search?q=1' }))).toMatchObject({
      jobType: 'param_discovery',
      target: 'a.example.com',
      params: { scheme: 'https', path: '/search' },
    })
  })

  it('re-verifies a cve_new via the nuclei template with its cve id + long cooldown', () => {
    const plan = planRetestScan(f({ type: 'cve_new', ip: '1.2.3.4', data: { cveId: 'CVE-2024-1', hostnames: ['1.2.3.4', 'host.example.com'], kev: true } }))
    expect(plan).toMatchObject({ jobType: 'cve_verify', target: 'host.example.com', params: { cveId: 'CVE-2024-1', ip: '1.2.3.4', kev: true } })
    expect(plan?.cooldownMs).toBeGreaterThan(0)
  })

  it('returns null when a targeted type has no scannable host', () => {
    expect(planRetestScan(f({ type: 'nuclei', host: null }))).toBeNull()
    expect(planRetestScan(f({ type: 'cve_new', ip: '1.2.3.4', data: { cveId: 'CVE-2024-1', hostnames: ['1.2.3.4'] } }))).toBeNull() // IP-only, no scannable name
  })

  it('returns null for types with no clean single-asset re-detection', () => {
    for (const type of ['leak', 'secret', 'authz', 'asset_change']) {
      expect(planRetestScan(f({ type, host: 'a.example.com', data: { cveId: 'x' } }))).toBeNull()
    }
  })
})
