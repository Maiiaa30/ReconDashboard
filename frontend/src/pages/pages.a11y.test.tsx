import { screen } from '@testing-library/react'
import { describe, it, vi } from 'vitest'
import { expectNoAxeViolations, renderPage } from '../test/renderPage'

// Per-page accessibility sweeps. Each page is rendered the way the Shell mounts it
// (inside the app-state/toast/confirm providers and a <main> landmark) and audited
// with axe. The `../api` module is mocked so the app-state provider's mount load
// and each page's own initial fetch resolve to empty-but-valid shapes: an empty
// page still exercises the real heading/landmark/label/role structure, which is
// what these structural rules check.
//
// Extend the returns map + a new `it` block to bring another page under the sweep.
vi.mock('../api', () => {
  const ts = '2026-01-01T00:00:00.000Z'
  // One selected target so pages that gate their content on a domain render their
  // full structure (header + empty results) instead of a "select a target" stub.
  const domain = {
    id: 1, host: 'example.com', label: null, mode: 'passive_only', profile: null,
    owaspConfig: null, monitorIntervalHours: 0, lastMonitoredAt: null, scopeConfig: null,
    authorizedFrom: null, authorizedUntil: null, createdAt: ts, updatedAt: ts,
  }
  const returns: Record<string, unknown> = {
    // app-state provider (state.tsx) loads these on mount
    domains: { domains: [domain] },
    me: { user: { id: 1, username: 'operator', selectedDomainId: 1, totpEnabled: false } },
    setSelectedDomain: undefined,
    // page-specific loads (empty-but-valid shapes)
    audit: { entries: [], nextCursor: null },
    auditSummary: { total: 0, byAction: {} },
    jobs: { jobs: [] },
    notes: { notes: [] },
    meta: {
      scorer: 'rules', aiProvider: 'rules',
      scheduler: { enabled: false, intervalMinutes: 0 },
      discordConfigured: false,
      llm: { enabled: false, model: null },
      leaks: { enabled: false, provider: null },
      tools: {
        subfinder: true, nmap: true, nuclei: true, ffuf: true, chromium: true, dig: true,
        sqlmap: false, sslscan: false, katana: false, naabu: false, dalfox: false,
        wpenum: false, bypass403: false, methods: false, datastores: false,
      },
      wordlists: [],
      readiness: {
        checkedAt: 0,
        database: { ok: true, sizeBytes: 1000 },
        storage: { freeBytes: 5 * 1024 ** 3 },
        worker: { running: true, startedAt: 0, lastTickAt: 0, lanes: { passive: true, loud: true } },
        queue: { queued: 0, running: 0, failed: 0, lastActivityAt: null },
        capture: { enabled: false, extensionSeenAt: null },
        backup: { serverPassphraseConfigured: false },
      },
    },
    findings: { findings: [], nextCursor: null },
    subdomainsPage: { subdomains: [], nextCursor: null },
    subdomains: { subdomains: [] },
    screenshots: { screenshots: [] },
    owaspCatalog: { catalog: [], profileKeys: [] },
    backupStatus: { serverPassphraseConfigured: false },
    job: null,
  }
  const api = new Proxy(
    {},
    { get: (_t, prop: string) => vi.fn(async () => (prop in returns ? returns[prop] : {})) },
  )
  class ApiError extends Error {}
  return { api, ApiError }
})

// Imported after the mock is registered (vi.mock is hoisted above imports anyway).
const { Whois } = await import('./Whois')
const { CheckHost } = await import('./CheckHost')
const { Audit } = await import('./Audit')
const { Jobs } = await import('./Jobs')
const { Notes } = await import('./Notes')
const { SocialForensics } = await import('./SocialForensics')
const { LlmSecurity } = await import('./LlmSecurity')
const { Ports } = await import('./Ports')
const { Osint } = await import('./Osint')
const { Exposure } = await import('./Exposure')
const { Origin } = await import('./Origin')
const { Changes } = await import('./Changes')
const { Screenshots } = await import('./Screenshots')
const { Fuzzing } = await import('./Fuzzing')
const { Scans } = await import('./Scans')
const { Tools } = await import('./Tools')
const { Owasp } = await import('./Owasp')
const { Settings } = await import('./Settings')

const navigate = vi.fn()

describe('page accessibility sweep', () => {
  it('WHOIS lookup has no violations', async () => {
    const { container } = renderPage(<Whois />)
    await screen.findByRole('heading', { name: 'WHOIS' })
    await expectNoAxeViolations(container)
  })

  it('Check Host has no violations', async () => {
    const { container } = renderPage(<CheckHost />)
    await screen.findByRole('heading', { name: 'Check Host' })
    await expectNoAxeViolations(container)
  })

  it('Audit ledger has no violations', async () => {
    const { container } = renderPage(<Audit />)
    await screen.findByRole('heading', { name: 'Audit ledger' })
    await expectNoAxeViolations(container)
  })

  it('Activity log has no violations', async () => {
    const { container } = renderPage(<Jobs />)
    await screen.findByRole('heading', { name: 'Activity log' })
    await expectNoAxeViolations(container)
  })

  it('Notes has no violations', async () => {
    const { container } = renderPage(<Notes />)
    await screen.findByRole('heading', { name: 'Notes' })
    await expectNoAxeViolations(container)
  })

  it('Social Forensics has no violations', async () => {
    const { container } = renderPage(<SocialForensics />)
    await screen.findByRole('heading', { name: 'Social Forensics' })
    await expectNoAxeViolations(container)
  })

  it('LLM Security has no violations', async () => {
    const { container } = renderPage(<LlmSecurity />)
    await screen.findByRole('heading', { name: 'LLM Security' })
    await expectNoAxeViolations(container)
  })

  it('Ports has no violations', async () => {
    const { container } = renderPage(<Ports />)
    await screen.findByRole('heading', { name: 'Ports' })
    await expectNoAxeViolations(container)
  })

  it('OSINT has no violations', async () => {
    const { container } = renderPage(<Osint />)
    await screen.findByRole('heading', { name: 'OSINT' })
    await expectNoAxeViolations(container)
  })

  it('Exposure has no violations', async () => {
    const { container } = renderPage(<Exposure />)
    await screen.findByRole('heading', { name: 'Exposure' })
    await expectNoAxeViolations(container)
  })

  it('WAF / Origin has no violations', async () => {
    const { container } = renderPage(<Origin />)
    await screen.findByRole('heading', { name: 'WAF / Origin' })
    await expectNoAxeViolations(container)
  })

  it('Change history has no violations', async () => {
    const { container } = renderPage(<Changes navigate={navigate} />)
    await screen.findByRole('heading', { name: 'Change history' })
    await expectNoAxeViolations(container)
  })

  it('Screenshots has no violations', async () => {
    const { container } = renderPage(<Screenshots />)
    await screen.findByRole('heading', { name: 'Screenshots' })
    await expectNoAxeViolations(container)
  })

  it('Fuzzing has no violations', async () => {
    const { container } = renderPage(<Fuzzing />)
    await screen.findByRole('heading', { name: 'Fuzzing' })
    await expectNoAxeViolations(container)
  })

  it('Scans has no violations', async () => {
    const { container } = renderPage(<Scans />)
    await screen.findByRole('heading', { name: 'Scans' })
    await expectNoAxeViolations(container)
  })

  it('Tools has no violations', async () => {
    const { container } = renderPage(<Tools />)
    await screen.findByRole('heading', { name: 'Tools' })
    await expectNoAxeViolations(container)
  })

  it('OWASP Top 10 has no violations', async () => {
    const { container } = renderPage(<Owasp />)
    await screen.findByRole('heading', { name: 'OWASP Top 10' })
    await expectNoAxeViolations(container)
  })

  it('Settings has no violations', async () => {
    const { container } = renderPage(<Settings totpEnabled={false} />)
    await screen.findByRole('heading', { name: 'Settings' })
    await expectNoAxeViolations(container)
  })
})
