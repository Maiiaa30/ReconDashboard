// In-session handoff so the Traffic page can push a captured request into the
// Replay (Repeater) editor. A module singleton is enough: navigation between
// pages is client-side (no reload), so the value survives until Replay consumes
// it. Cleared on read so it doesn't leak into a later manual visit.
export interface PendingReplay {
  method: string
  url: string
  headers: [string, string][]
  body?: string | null
  // Which workbench tab to open the request in. Defaults to the Repeater.
  mode?: 'repeater' | 'intruder'
}

let pending: PendingReplay | null = null

export function setPendingReplay(r: PendingReplay): void {
  pending = r
}

export function takePendingReplay(): PendingReplay | null {
  const r = pending
  pending = null
  return r
}
