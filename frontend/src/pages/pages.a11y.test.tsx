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
  const returns: Record<string, unknown> = {
    // app-state provider (state.tsx) loads these on mount
    domains: { domains: [] },
    me: { user: { id: 1, username: 'operator', selectedDomainId: null, totpEnabled: false } },
    setSelectedDomain: undefined,
    // page-specific loads
    audit: { entries: [], nextCursor: null },
    auditSummary: { total: 0, byAction: {} },
    jobs: { jobs: [] },
    notes: { notes: [] },
    meta: { discordConfigured: false },
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
})
