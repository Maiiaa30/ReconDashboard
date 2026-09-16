// A tiny in-process pub/sub for "something changed" signals. The SSE endpoint
// (routes/events.ts) forwards these to connected clients so the UI can refresh
// immediately instead of only on its polling interval. Events carry NO data
// beyond a coarse kind (+ optional domain) — the client re-fetches through the
// normal endpoints, so a missed or dropped event just falls back to the poll.
//
// Deliberately minimal: one process, one operator, no Redis. Emitting is a
// best-effort fire-and-forget; a throwing subscriber can never break the caller.

export type AppEventKind = 'jobs' | 'findings' | 'runs'

export interface AppEvent {
  kind: AppEventKind
  domainId?: number | null
}

type Listener = (ev: AppEvent) => void

const listeners = new Set<Listener>()

/** Subscribe to events; returns an unsubscribe function. */
export function subscribe(fn: Listener): () => void {
  listeners.add(fn)
  return () => listeners.delete(fn)
}

/** Fire an event to all subscribers. Never throws — a bad listener is isolated. */
export function emit(ev: AppEvent): void {
  for (const fn of listeners) {
    try {
      fn(ev)
    } catch {
      /* a subscriber must never break the emitter */
    }
  }
}

// Convenience emitters for the call sites.
export const emitJobs = (): void => emit({ kind: 'jobs' })
export const emitFindings = (domainId?: number | null): void => emit({ kind: 'findings', domainId })
export const emitRuns = (domainId?: number | null): void => emit({ kind: 'runs', domainId })

// Test-only: drop all subscribers so a test can start clean.
export function _resetForTest(): void {
  listeners.clear()
}
