import { act, renderHook } from '@testing-library/react'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { usePoll } from './state'

describe('usePoll', () => {
  afterEach(() => vi.useRealTimers())

  it('does not overlap a slow async poll and aborts it on cleanup', async () => {
    vi.useFakeTimers()
    const signals: AbortSignal[] = []
    const poll = vi.fn((signal: AbortSignal) => {
      signals.push(signal)
      return new Promise<void>(() => {})
    })

    const { unmount } = renderHook(() => usePoll(poll, 1_000))
    await act(async () => vi.advanceTimersByTimeAsync(5_000))

    expect(poll).toHaveBeenCalledTimes(1)
    expect(signals[0].aborted).toBe(false)

    unmount()
    expect(signals[0].aborted).toBe(true)
  })

  it('starts a fresh lifecycle when the reset key changes', async () => {
    vi.useFakeTimers()
    const signals: AbortSignal[] = []
    const poll = vi.fn((signal: AbortSignal) => {
      signals.push(signal)
      return new Promise<void>(() => {})
    })

    const { rerender } = renderHook(
      ({ targetId }) => usePoll(poll, 1_000, true, targetId),
      { initialProps: { targetId: 1 } },
    )
    await act(async () => vi.advanceTimersByTimeAsync(0))
    rerender({ targetId: 2 })
    await act(async () => vi.advanceTimersByTimeAsync(0))

    expect(poll).toHaveBeenCalledTimes(2)
    expect(signals[0].aborted).toBe(true)
    expect(signals[1].aborted).toBe(false)
  })
})
