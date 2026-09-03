// Global connection status derived from the single transport choke point in
// http.ts. Pollers across the app used to swallow failures silently, so a
// dropped Tailscale link or an expired session produced a frozen-looking UI
// with no explanation. This tiny framework-free store lets the transport report
// what it sees and lets React surface it (see useConnection / ConnectionBanner).

export interface ConnectionState {
  // false once a request fails at the network level (backend/tailnet
  // unreachable); back to true on the next successful response.
  online: boolean
  // true once a request comes back 401 while the app believed it was authed;
  // the app routes to the login screen and clears it.
  sessionExpired: boolean
}

type Listener = (state: ConnectionState) => void

let state: ConnectionState = { online: true, sessionExpired: false }
const listeners = new Set<Listener>()

function set(patch: Partial<ConnectionState>): void {
  const next = { ...state, ...patch }
  if (next.online === state.online && next.sessionExpired === state.sessionExpired) return
  state = next
  for (const listener of listeners) listener(state)
}

export function getConnection(): ConnectionState {
  return state
}

export function subscribeConnection(listener: Listener): () => void {
  listeners.add(listener)
  return () => {
    listeners.delete(listener)
  }
}

export function markOnline(): void {
  set({ online: true })
}

export function markOffline(): void {
  set({ online: false })
}

export function markSessionExpired(): void {
  set({ sessionExpired: true })
}

export function clearSessionExpired(): void {
  set({ sessionExpired: false })
}

// Test-only: restore the module singleton between cases.
export function resetConnection(): void {
  state = { online: true, sessionExpired: false }
}
