import { afterEach, describe, expect, it, vi } from 'vitest'
import { api } from './api'

// Characterization guard for the split of the monolithic `api.ts` into
// per-domain clients. This is the public method surface (the pre-split set plus
// any deliberate additions since); if a method is dropped, renamed, or
// duplicated while the clients are refactored further, this snapshot fails
// loudly. Add a new method here in the same commit that introduces it.
const EXPECTED_METHODS = [
  'acknowledgeNew',
  'acknowledgeToday',
  'adviseIntel',
  'apiDiscovery',
  'assessmentComparison',
  'assessmentRun',
  'assessmentRuns',
  'assetDetail',
  'assets',
  'attachEvidence',
  'audit',
  'auditSummary',
  'authzDiff',
  'backupRestore',
  'backupStatus',
  'backupVerify',
  'bulkUpdateFindings',
  'cancelAssessmentRun',
  'cancelAssessmentTarget',
  'cancelJob',
  'capture',
  'captures',
  'capturesSummary',
  'captureScreenshots',
  'captureStatus',
  'chainSuggestions',
  'changePassword',
  'changeUsername',
  'checkEmailLeak',
  'checkHost',
  'checkLeaks',
  'clearCaptures',
  'clearReplayHistory',
  'codeLeaks',
  'correlate',
  'createAssessmentReport',
  'createAssessmentRun',
  'createDomain',
  'createDrawing',
  'createMatchReplace',
  'createNote',
  'createPayloadSet',
  'createSnapshot',
  'deleteCapture',
  'deleteDomain',
  'deleteDrawing',
  'deleteIdentity',
  'deleteMatchReplace',
  'deleteNote',
  'deletePayloadSet',
  'deleteSnapshot',
  'disableTotp',
  'discover',
  'dnsPermute',
  'domains',
  'domainsOverview',
  'drawing',
  'drawings',
  'enableTotp',
  'encodePayload',
  'enroll',
  'explainIntruderRow',
  'exposure',
  'ffuf',
  'findingLinks',
  'findings',
  'findingsSummary',
  'findOrigin',
  'generateNarrative',
  'home',
  'identities',
  'injectConfirm',
  'intruder',
  'job',
  'jobs',
  'jwtConfuse',
  'leaks',
  'login',
  'logout',
  'matchReplaceRules',
  'me',
  'meta',
  'methodology',
  'mutatePayload',
  'narrateChain',
  'nextActions',
  'nmap',
  'nmapSweep',
  'notes',
  'nuclei',
  'osint',
  'owaspCatalog',
  'paramDiscovery',
  'payloads',
  'purgeDomainData',
  'replayHistory',
  'replayHistoryDetail',
  'replaySend',
  'reportPdfUrl',
  'retestFinding',
  'retryAssessmentRun',
  'retryAssessmentTarget',
  'runOwasp',
  'runTool',
  'saveIdentity',
  'screenshots',
  'screenshotUrl',
  'secretTriage',
  'sendNoteToDiscord',
  'setDomainMode',
  'setMethodologyStep',
  'setSelectedDomain',
  'sitemap',
  'snapshots',
  'snapshotUrl',
  'subdomains',
  'subdomainsPage',
  'subdomainsSummary',
  'today',
  'triageSuggest',
  'updateDomain',
  'updateDrawing',
  'updateFinding',
  'updateMatchReplace',
  'updateNextAction',
  'updateNote',
  'verifyCve',
  'whois',
].sort()

function jsonResponse(body: unknown): Response {
  return { ok: true, status: 200, text: async () => JSON.stringify(body) } as Response
}

describe('api facade composition', () => {
  afterEach(() => vi.unstubAllGlobals())

  it('exposes exactly the pre-split method surface', () => {
    expect(Object.keys(api).sort()).toEqual(EXPECTED_METHODS)
  })

  it('every entry is callable', () => {
    for (const key of EXPECTED_METHODS) {
      expect(typeof (api as Record<string, unknown>)[key]).toBe('function')
    }
  })

  // One request from a few different clients confirms the spread kept each
  // client wired to the real transport (URL + verb), not just present by name.
  it('routes composed client methods through the shared transport', async () => {
    const fetchMock = vi.fn().mockResolvedValue(jsonResponse({}))
    vi.stubGlobal('fetch', fetchMock)

    await api.me() // auth
    await api.subdomains(7) // recon
    await api.correlate(3) // intel
    await api.replaySend({ domainId: 1, method: 'GET', url: 'https://x.test' }) // replay
    await api.audit({ domainId: 2, limit: 5 }) // content

    const calls = fetchMock.mock.calls.map((c) => [c[0], (c[1] as RequestInit | undefined)?.method ?? 'GET'])
    expect(calls).toEqual([
      ['/api/auth/me', 'GET'],
      ['/api/domains/7/subdomains', 'GET'],
      ['/api/domains/3/correlate', 'GET'],
      ['/api/replay/send', 'POST'],
      ['/api/audit?domainId=2&limit=5', 'GET'],
    ])
  })

  // Pure URL-builders return strings without touching the network.
  it('keeps URL-builder helpers pure', () => {
    expect(api.screenshotUrl(4, 'a.example.com')).toBe('/api/domains/4/screenshot?host=a.example.com')
    expect(api.snapshotUrl(9, 'html')).toBe('/api/report/snapshots/9?format=html')
    expect(api.reportPdfUrl(9)).toBe('/api/export/report/9.pdf')
  })
})
