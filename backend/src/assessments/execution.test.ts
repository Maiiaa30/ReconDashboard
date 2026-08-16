import { describe, expect, it } from 'vitest'
import { classifyJobExecution } from './execution'

describe('assessment execution truth', () => {
  it('does not count an unavailable scanner as completed coverage', () => {
    expect(classifyJobExecution({ status: 'done', result: JSON.stringify({ available: false, note: 'nmap binary not installed' }) }))
      .toMatchObject({ outcome: 'unavailable', reason: 'nmap binary not installed' })
  })

  it('marks unreachable and aborted executions as degraded', () => {
    expect(classifyJobExecution({ status: 'done', result: JSON.stringify({ reachable: false, count: 0 }) }).outcome).toBe('degraded')
    expect(classifyJobExecution({ status: 'done', result: JSON.stringify({ available: true, aborted: true, hits: 2 }) }).outcome).toBe('degraded')
  })

  it('detects nested provider errors in an otherwise completed aggregate', () => {
    const result = { domain: 'example.com', dns: { a: ['203.0.113.1'] }, wayback: { error: 'provider timed out' } }
    expect(classifyJobExecution({ status: 'done', result: JSON.stringify(result) })).toMatchObject({ outcome: 'degraded' })
  })

  it('keeps a clean zero-finding scan completed', () => {
    expect(classifyJobExecution({ status: 'done', result: JSON.stringify({ available: true, target: 'example.com', count: 0 }) }))
      .toMatchObject({ outcome: 'completed', reason: null })
  })

  it('honors an explicit handler outcome contract before legacy inference', () => {
    const result = { available: true, execution: { outcome: 'unavailable', reason: 'provider quota exhausted', summary: ['provider: censys'] } }
    expect(classifyJobExecution({ status: 'done', result: JSON.stringify(result) })).toEqual({
      outcome: 'unavailable', reason: 'provider quota exhausted', summary: ['provider: censys'],
    })
  })
})
