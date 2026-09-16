import { afterEach, describe, expect, it, vi } from 'vitest'
import { _resetForTest, emit, emitFindings, emitJobs, subscribe } from './bus'

afterEach(() => _resetForTest())

describe('event bus', () => {
  it('delivers an emitted event to every subscriber', () => {
    const a = vi.fn()
    const b = vi.fn()
    subscribe(a)
    subscribe(b)
    emit({ kind: 'jobs' })
    expect(a).toHaveBeenCalledWith({ kind: 'jobs' })
    expect(b).toHaveBeenCalledWith({ kind: 'jobs' })
  })

  it('stops delivering after unsubscribe', () => {
    const fn = vi.fn()
    const off = subscribe(fn)
    emitJobs()
    off()
    emitJobs()
    expect(fn).toHaveBeenCalledTimes(1)
  })

  it('carries the domain id on a findings event', () => {
    const fn = vi.fn()
    subscribe(fn)
    emitFindings(42)
    expect(fn).toHaveBeenCalledWith({ kind: 'findings', domainId: 42 })
  })

  it('isolates a throwing subscriber so the emitter and others still run', () => {
    const bad = vi.fn(() => {
      throw new Error('boom')
    })
    const good = vi.fn()
    subscribe(bad)
    subscribe(good)
    expect(() => emitJobs()).not.toThrow()
    expect(good).toHaveBeenCalledOnce()
  })
})
