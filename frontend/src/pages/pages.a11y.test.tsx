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
    findingsSummary: { total: 0, byStatus: {}, bySeverity: {} },
    subdomainsPage: { subdomains: [], nextCursor: null },
    subdomainsSummary: { total: 0, newCount: 0 },
    subdomains: { subdomains: [] },
    screenshots: { screenshots: [] },
    owaspCatalog: { catalog: [], profileKeys: [] },
    backupStatus: { serverPassphraseConfigured: false },
    job: null,
    // rich data pages
    home: { overview: [], topFindings: [], recentChanges: [] },
    today: null,
    domainsOverview: { overview: [] },
    correlate: { paths: [], signatureClusters: [] },
    chainSuggestions: { chains: [] },
    nextActions: { actions: [] },
    methodology: { tech: [], ports: [], skills: [] },
    assessmentRuns: { runs: [] },
    snapshots: { snapshots: [] },
    identities: { identities: [] },
    assets: { assets: [] },
    captures: { captures: [], nextCursor: null },
    capturesSummary: { total: 0, byMethod: {} },
    captureStatus: { enabled: false, extensionSeenAt: null },
    drawings: { drawings: [] },
    leaks: { enabled: false, provider: null, autoDaily: false, pending: false, lastCheckedAt: null, findings: [] },
    matchReplaceRules: { rules: [] },
  }
  // Any method a default-rendered panel loads that is not in `returns` resolves to
  // this: a value whose every property reads as an empty array, so a
  // `.then((r) => setX(r.some))` followed by `r.some.filter(...)` cannot crash the
  // render regardless of promise timing (an unmapped call would otherwise be a
  // flaky, act-window-dependent failure). Explicit fixtures above still win where
  // the shape matters.
  const safeEmpty = new Proxy({}, { get: () => [] })
  const api = new Proxy(
    {},
    { get: (_t, prop: string) => vi.fn(async () => (prop in returns ? returns[prop] : safeEmpty)) },
  )
  class ApiError extends Error {}
  return { api, ApiError }
})

// Excalidraw needs a real canvas/ResizeObserver, which jsdom lacks. The Canvas
// page lazy-loads it inside a Suspense boundary; stub it so the page shell (the
// part we audit) renders without pulling in the real editor.
vi.mock('@excalidraw/excalidraw', () => ({ Excalidraw: () => null }))

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
const { Home } = await import('./Home')
const { Findings } = await import('./Findings')
const { Domains } = await import('./Domains')
const { Intel } = await import('./Intel')
const { Replay } = await import('./Replay')
const { ApiSurface } = await import('./ApiSurface')
const { Assets } = await import('./Assets')
const { Reports } = await import('./Reports')
const { Methodology } = await import('./Methodology')
const { NextActions } = await import('./NextActions')
const { CommandCenter } = await import('./CommandCenter')
const { Subdomains } = await import('./Subdomains')
const { Traffic } = await import('./Traffic')
const { Canvas } = await import('./Canvas')
const { AssessmentRuns } = await import('./AssessmentRuns')
const { ScanProfiles } = await import('./ScanProfiles')
const { Readiness } = await import('./Readiness')
const { DataLeaks } = await import('./DataLeaks')

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

  it('Engagement overview (Home) has no violations', async () => {
    const { container } = renderPage(<Home navigate={navigate} />)
    await screen.findByRole('heading', { name: 'Engagement overview' })
    await expectNoAxeViolations(container)
  })

  it('Findings has no violations', async () => {
    const { container } = renderPage(<Findings navigate={navigate} />)
    await screen.findByRole('heading', { name: 'Findings' })
    await expectNoAxeViolations(container)
  })

  it('Scope & targets (Domains) has no violations', async () => {
    const { container } = renderPage(<Domains />)
    await screen.findByRole('heading', { name: 'Scope & targets' })
    await expectNoAxeViolations(container)
  })

  it('Intel has no violations', async () => {
    const { container } = renderPage(<Intel navigate={navigate} />)
    await screen.findByRole('heading', { name: 'Intel' })
    await expectNoAxeViolations(container)
  })

  it('Replay has no violations', async () => {
    const { container } = renderPage(<Replay />)
    await screen.findByRole('heading', { name: 'Replay' })
    await expectNoAxeViolations(container)
  })

  it('API Surface has no violations', async () => {
    const { container } = renderPage(<ApiSurface navigate={navigate} />)
    await screen.findByRole('heading', { name: 'API Surface' })
    await expectNoAxeViolations(container)
  })

  it('Asset inventory has no violations', async () => {
    const { container } = renderPage(<Assets navigate={navigate} />)
    await screen.findByRole('heading', { name: 'Asset inventory' })
    await expectNoAxeViolations(container)
  })

  it('Reports has no violations', async () => {
    const { container } = renderPage(<Reports navigate={navigate} />)
    await screen.findByRole('heading', { name: 'Reports' })
    await expectNoAxeViolations(container)
  })

  it('Methodology has no violations', async () => {
    const { container } = renderPage(<Methodology navigate={navigate} />)
    await screen.findByRole('heading', { name: 'Methodology' })
    await expectNoAxeViolations(container)
  })

  it('Next actions has no violations', async () => {
    const { container } = renderPage(<NextActions navigate={navigate} />)
    await screen.findByRole('heading', { name: 'Next actions' })
    await expectNoAxeViolations(container)
  })

  it('Command center has no violations', async () => {
    const { container } = renderPage(<CommandCenter navigate={navigate} />)
    await screen.findByRole('heading', { name: 'Command center' })
    await expectNoAxeViolations(container)
  })

  it('Subdomains has no violations', async () => {
    const { container } = renderPage(<Subdomains />)
    await screen.findByRole('heading', { name: 'Subdomains' })
    await expectNoAxeViolations(container)
  })

  it('Traffic has no violations', async () => {
    const { container } = renderPage(<Traffic navigate={navigate} />)
    await screen.findByRole('heading', { name: 'Traffic' })
    await expectNoAxeViolations(container)
  })

  it('Canvas has no violations', async () => {
    const { container } = renderPage(<Canvas />)
    await screen.findByRole('heading', { name: 'Canvas' })
    await expectNoAxeViolations(container)
  })

  it('Assessment runs has no violations', async () => {
    const { container } = renderPage(<AssessmentRuns navigate={navigate} />)
    await screen.findByRole('heading', { name: 'Assessment runs' })
    await expectNoAxeViolations(container)
  })

  it('Assessment profiles (ScanProfiles) has no violations', async () => {
    const { container } = renderPage(<ScanProfiles navigate={navigate} />)
    await screen.findByRole('heading', { name: 'Assessment profiles' })
    await expectNoAxeViolations(container)
  })

  it('Readiness has no violations', async () => {
    const { container } = renderPage(<Readiness />)
    await screen.findByRole('heading', { name: 'Readiness' })
    await expectNoAxeViolations(container)
  })

  it('Data Leaks has no violations', async () => {
    const { container } = renderPage(<DataLeaks />)
    await screen.findByRole('heading', { name: 'Data Leaks' })
    await expectNoAxeViolations(container)
  })
})
