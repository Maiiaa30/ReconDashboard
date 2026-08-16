import { describe, expect, it } from 'vitest'
import type { MetaStatus } from '../api'
import { summarizeReadiness } from './Readiness'

const meta = {
  tools: { subfinder: true, nmap: true, nuclei: true, ffuf: true, chromium: true },
  readiness: {
    database: { ok: true },
    storage: { freeBytes: 5 * 1024 ** 3 },
    worker: { running: true, lastTickAt: 99_000 },
  },
} as unknown as MetaStatus

describe('readiness summary', () => {
  it('reports ready when every core check passes', () => {
    expect(summarizeReadiness(meta, 100_000)).toEqual({ tone: 'green', label: 'Ready', issues: [] })
  })

  it('treats stale worker health as an action-required failure', () => {
    const stale = { ...meta, readiness: { ...meta.readiness, worker: { ...meta.readiness.worker, lastTickAt: 50_000 } } }
    expect(summarizeReadiness(stale, 100_000).tone).toBe('red')
  })

  it('reports missing scanner tools as partial readiness', () => {
    const missing = { ...meta, tools: { ...meta.tools, nuclei: false } }
    expect(summarizeReadiness(missing, 100_000)).toMatchObject({ tone: 'amber', issues: ['missing tools: nuclei'] })
  })
})
