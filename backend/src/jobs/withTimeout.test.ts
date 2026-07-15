import { describe, expect, it, vi } from 'vitest'

// worker.ts imports the DB on load; mock it so this pure-logic test needs no DB.
vi.mock('../db/index', () => ({ db: {} }))

import { withTimeout } from './worker'

describe('withTimeout (worker job guard)', () => {
  it('resolves with the value when the work finishes in time', async () => {
    const onTimeout = vi.fn()
    await expect(withTimeout(Promise.resolve('ok'), 1000, onTimeout)).resolves.toBe('ok')
    expect(onTimeout).not.toHaveBeenCalled()
  })

  it('rejects and fires onTimeout (the abort) when the work overruns', async () => {
    const onTimeout = vi.fn()
    const slow = new Promise((r) => setTimeout(() => r('late'), 100))
    await expect(withTimeout(slow, 5, onTimeout)).rejects.toThrow(/timed out/)
    expect(onTimeout).toHaveBeenCalledOnce() // the timeout aborts the job's signal
  })

  it('propagates a rejection from the work without firing onTimeout', async () => {
    const onTimeout = vi.fn()
    await expect(withTimeout(Promise.reject(new Error('boom')), 1000, onTimeout)).rejects.toThrow('boom')
    expect(onTimeout).not.toHaveBeenCalled()
  })
})
