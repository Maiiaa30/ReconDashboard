// Types, constants, pure helpers and tiny UI shared across the Replay panels.

// A request handed to the editor (headers as a list of pairs).
export type BuiltReq = { method: string; url: string; headers: [string, string][]; body?: string | null }

// A composed request as the panels build it for the API (headers as a map).
export type BuiltRequest = { method: string; url: string; headers: Record<string, string>; body?: string; followRedirects: boolean }

export const METHODS = ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS'] as const
export const PAYLOAD_MARKER = '{{PAYLOAD}}'

// Parse a "Name: Value" textarea into a header map (blank/invalid lines skipped).
export function parseHeaders(text: string): Record<string, string> {
  const out: Record<string, string> = {}
  for (const line of text.split(/\r?\n/)) {
    const t = line.trim()
    if (!t) continue
    const idx = t.indexOf(':')
    if (idx <= 0) continue
    const name = t.slice(0, idx).trim()
    if (name) out[name] = t.slice(idx + 1).trim()
  }
  return out
}

// Response status → badge tone.
export function statusTone(s: number): 'green' | 'amber' | 'red' | 'blue' | 'zinc' {
  if (s === 0) return 'red'
  if (s >= 200 && s < 300) return 'green'
  if (s >= 300 && s < 400) return 'blue'
  if (s === 401 || s === 403 || s === 429) return 'amber'
  if (s >= 400) return 'red'
  return 'zinc'
}

// A small numeric-only labelled input (Intruder / Inject / Authz).
export function NumField({ label, value, onChange }: { label: string; value: string; onChange: (s: string) => void }) {
  return (
    <label className="inline-flex flex-col gap-0.5">
      <span className="text-[10px] uppercase tracking-wide text-zinc-600">{label}</span>
      <input
        value={value}
        onChange={(e) => onChange(e.target.value.replace(/[^\d]/g, ''))}
        inputMode="numeric"
        className="w-24 rounded-lg border border-hair bg-ink-950 px-2 py-1 font-mono text-xs outline-none focus:border-accent-500"
      />
    </label>
  )
}
