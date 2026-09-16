import { useEffect, useRef } from 'react'

// One shared Server-Sent-Events connection to /api/events. The server pushes
// coarse "something changed" signals ({ kind }); a page subscribes to a kind and
// refreshes its own data when one arrives. This ACCELERATES the existing polling
// — it never replaces it — so if the stream drops (or the browser lacks
// EventSource, or the connection is down) the page still updates on its poll.

export type AppEventKind = 'jobs' | 'findings' | 'runs'

type Cb = () => void
const listeners: Record<AppEventKind, Set<Cb>> = { jobs: new Set(), findings: new Set(), runs: new Set() }

let source: EventSource | null = null
// Coalesce bursts (a running job emits a progress signal often) so a page
// refreshes at most once per window per kind instead of per event.
const COALESCE_MS = 300
const pending: Record<AppEventKind, ReturnType<typeof setTimeout> | null> = { jobs: null, findings: null, runs: null }

function dispatch(kind: AppEventKind) {
  if (pending[kind]) return
  pending[kind] = setTimeout(() => {
    pending[kind] = null
    for (const cb of listeners[kind]) {
      try {
        cb()
      } catch {
        /* a page callback must never break the dispatcher */
      }
    }
  }, COALESCE_MS)
}

function ensureConnected() {
  if (source || typeof EventSource === 'undefined') return
  try {
    source = new EventSource('/api/events')
    source.onmessage = (e) => {
      try {
        const ev = JSON.parse(e.data) as { kind?: AppEventKind }
        if (ev.kind && listeners[ev.kind]) dispatch(ev.kind)
      } catch {
        /* ignore malformed frames */
      }
    }
    // EventSource reconnects on its own after a transient error; only tear down
    // if the browser marks it permanently CLOSED, so ensureConnected re-opens it.
    source.onerror = () => {
      if (source && source.readyState === EventSource.CLOSED) {
        source = null
      }
    }
  } catch {
    source = null // stream unavailable — polling covers it
  }
}

function maybeDisconnect() {
  const anyLeft = listeners.jobs.size || listeners.findings.size || listeners.runs.size
  if (!anyLeft && source) {
    source.close()
    source = null
  }
}

/**
 * Subscribe a React component to a change-signal kind. The callback runs
 * (coalesced) whenever the server reports that kind changed. Purely additive to
 * the component's own polling.
 */
export function useAppEvent(kind: AppEventKind, cb: Cb) {
  // Keep the latest callback without re-subscribing every render.
  const ref = useRef(cb)
  ref.current = cb
  useEffect(() => {
    const listener: Cb = () => ref.current()
    listeners[kind].add(listener)
    ensureConnected()
    return () => {
      listeners[kind].delete(listener)
      maybeDisconnect()
    }
  }, [kind])
}
