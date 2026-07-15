import { describe, expect, it, vi, beforeEach } from 'vitest'

// Control the LLM: llmEnabled + llmComplete/llmCompleteJson are all mocked so the
// suggest-only logic (validation, filtering, fail-soft) is testable offline.
const llm = { enabled: true, text: null as string | null, json: null as unknown }
vi.mock('../util/llm', () => ({
  llmEnabled: () => llm.enabled,
  llmComplete: async () => llm.text,
  llmCompleteJson: async () => llm.json,
}))
// Stub the data sources these assists read (no DB in this unit test).
vi.mock('../domains/store', () => ({ getDomain: (id: number) => (id === 1 ? { id: 1, host: 't.com' } : undefined) }))
vi.mock('../jobs/queue', () => ({
  getJob: (id: number) =>
    id === 5
      ? { id: 5, type: 'intruder', result: JSON.stringify({ baseline: { status: 200, length: 100 }, interesting: [{ payload: 'x', status: 500, length: 20, timeMs: 90, bodyExcerpt: 'stack trace' }] }) }
      : undefined,
}))
vi.mock('../findings/store', () => ({ listFindings: () => [] }))

import { explainIntruderRow, narrateChain, suggestPayloadMutation, suggestSecretTriage } from './assists'

describe('AI assists — fail-soft when disabled', () => {
  beforeEach(() => {
    llm.enabled = false
    llm.text = null
    llm.json = null
  })
  it('every assist returns enabled:false + a note and never throws', async () => {
    expect((await explainIntruderRow(5, 0)).enabled).toBe(false)
    const mut = await suggestPayloadMutation("' OR 1=1")
    expect(mut.enabled).toBe(false)
    expect(mut.chains).toEqual([])
    expect((await suggestSecretTriage(1)).enabled).toBe(false)
    expect((await narrateChain(1, 'x')).enabled).toBe(false)
  })
})

describe('suggestPayloadMutation validation', () => {
  beforeEach(() => {
    llm.enabled = true
  })
  it('keeps only chains built from real transform names', async () => {
    llm.json = { chains: [['url'], ['base64', 'url'], ['not-a-transform'], ['url', 'evil']] }
    const out = await suggestPayloadMutation("<script>")
    expect(out.chains).toEqual([['url'], ['base64', 'url'], ['url']]) // invalid names dropped
  })
  it('notes when the model returns nothing usable', async () => {
    llm.json = { chains: [['bogus']] }
    const out = await suggestPayloadMutation("x")
    expect(out.chains).toEqual([])
    expect(out.note).toMatch(/no valid encoder/i)
  })
})

describe('explainIntruderRow', () => {
  beforeEach(() => {
    llm.enabled = true
  })
  it('returns the model explanation for a real row', async () => {
    llm.text = 'The 500 with a stack trace suggests an unhandled injection.'
    const out = await explainIntruderRow(5, 0)
    expect(out.explanation).toMatch(/stack trace/i)
  })
  it('handles a missing job cleanly', async () => {
    const out = await explainIntruderRow(999, 0)
    expect(out.enabled).toBe(true)
    expect(out.note).toMatch(/not found/i)
  })
})
