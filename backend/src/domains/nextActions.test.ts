import { describe, expect, it } from 'vitest'
import { buildNextActions, type NextActionInputs } from './nextActions'

function inputs(patch: Partial<NextActionInputs> = {}): NextActionInputs {
  return {
    domainHost: 'example.com',
    findings: [],
    latestRun: { id: 8, name: 'Full assessment', status: 'completed' },
    methodology: { tech: [], ports: [], skills: [] },
    chains: [],
    ...patch,
  }
}

describe('prioritized next actions', () => {
  it('puts grounded critical attack chains ahead of incomplete assessment coverage', () => {
    const actions = buildNextActions(inputs({
      latestRun: { id: 8, name: 'Full assessment', status: 'partial' },
      chains: [{ id: 'chain:git-dump:4', title: 'Dump exposed repository', rationale: 'A confirmed .git repository is exposed.', severity: 'critical', findingIds: [4], action: { kind: 'katana', target: 'example.com' } }],
    }))
    expect(actions.map((action) => action.source).slice(0, 2)).toEqual(['attack_chain', 'assessment'])
    expect(actions[0]).toMatchObject({ priority: 99, mode: 'loud', page: 'intel' })
  })

  it('explains and ranks material findings by their stored score', () => {
    const actions = buildNextActions(inputs({
      findings: [
        { id: 1, type: 'owasp', status: 'open', score: 45, data: { name: 'Missing CSP', url: 'https://example.com' } },
        { id: 2, type: 'nuclei', status: 'confirmed', score: 92, data: { name: 'Remote code execution', target: 'api.example.com' } },
      ] as any,
    }))
    expect(actions[0]).toMatchObject({ key: 'finding:2:triage', risk: 'critical', priority: 98, target: 'api.example.com' })
    expect(actions[0].why).toContain('confirmed')
  })

  it('distinguishes passive and loud methodology actions and links their modules', () => {
    const actions = buildNextActions(inputs({
      methodology: {
        tech: [], ports: [], skills: [{
          id: 'web', name: 'Web baseline', description: '', applicable: true, reason: 'baseline', coverage: 0,
          steps: [
            { key: 'discover', label: 'Discover hosts', why: 'map surface', status: 'todo', manual: false, action: { kind: 'discover' } },
            { key: 'nuclei', label: 'Run nuclei', why: 'test templates', status: 'todo', manual: false, action: { kind: 'nuclei' } },
          ],
        }],
      },
    }))
    expect(actions.find((action) => action.key.endsWith(':discover'))).toMatchObject({ mode: 'passive', page: 'subdomains', automation: 'automated' })
    expect(actions.find((action) => action.key.endsWith(':nuclei'))).toMatchObject({ mode: 'loud', page: 'scans', automation: 'automated' })
  })

  it('recommends a passive baseline when no assessment exists', () => {
    expect(buildNextActions(inputs({ latestRun: null }))[0]).toMatchObject({ key: 'assessment:start-baseline', mode: 'passive', page: 'profiles' })
  })
})
