import { useMemo, useState } from 'react'
import { KeyRound } from 'lucide-react'
import { Badge, Card } from '../../components/ui'

function b64urlToJson(part: string): Record<string, unknown> | null {
  try {
    const b64 = part.replace(/-/g, '+').replace(/_/g, '/')
    const bin = atob(b64)
    const bytes = Uint8Array.from(bin, (c) => c.charCodeAt(0))
    return JSON.parse(new TextDecoder().decode(bytes))
  } catch {
    return null
  }
}

export function JwtInspector() {
  const [token, setToken] = useState('')
  const parsed = useMemo(() => {
    const t = token.trim()
    if (!t) return null
    const parts = t.split('.')
    if (parts.length < 2) return { error: 'Not a JWT (expected header.payload.signature).' }
    const header = b64urlToJson(parts[0])
    const payload = b64urlToJson(parts[1])
    if (!header || !payload) return { error: 'Could not decode the JWT segments (invalid base64url).' }
    return { header, payload, hasSig: parts.length >= 3 && !!parts[2] }
  }, [token])

  const alg = parsed && 'header' in parsed ? String((parsed.header as any).alg ?? '') : ''
  const exp = parsed && 'payload' in parsed ? Number((parsed.payload as any).exp) : NaN
  const expired = Number.isFinite(exp) && exp * 1000 < Date.now()

  return (
    <Card>
      <div className="mb-2 flex items-center gap-2">
        <KeyRound size={16} className="text-amber-400" />
        <h2 className="text-sm font-semibold text-zinc-200">JWT inspector</h2>
        <span className="text-xs text-zinc-600">decodes locally — nothing is sent anywhere</span>
      </div>
      <textarea
        value={token}
        onChange={(e) => setToken(e.target.value)}
        placeholder="Paste a JWT (eyJ…) to decode its header and claims"
        rows={3}
        className="block w-full rounded-lg border border-hair bg-ink-950 px-3 py-2 font-mono text-xs outline-none focus:border-accent-500"
      />
      {parsed && 'error' in parsed && <p className="mt-2 text-sm text-amber-400">{parsed.error}</p>}
      {parsed && 'header' in parsed && (
        <div className="mt-3 space-y-2">
          <div className="flex flex-wrap items-center gap-2 text-xs">
            <Badge tone={alg.toLowerCase() === 'none' ? 'red' : 'zinc'}>alg: {alg || '—'}</Badge>
            {alg.toLowerCase() === 'none' && <span className="text-red-300">⚠ &quot;none&quot; algorithm — signature not enforced</span>}
            {Number.isFinite(exp) && <Badge tone={expired ? 'red' : 'green'}>{expired ? 'expired' : 'exp valid'}</Badge>}
            {!parsed.hasSig && <Badge tone="amber">no signature segment</Badge>}
          </div>
          <div className="grid gap-2 md:grid-cols-2">
            <JsonBlock label="Header" value={parsed.header} />
            <JsonBlock label="Payload (claims)" value={parsed.payload} />
          </div>
        </div>
      )}
    </Card>
  )
}

function JsonBlock({ label, value }: { label: string; value: unknown }) {
  return (
    <div>
      <div className="mb-1 text-[10px] uppercase tracking-wide text-zinc-600">{label}</div>
      <pre className="max-h-56 overflow-auto rounded-lg border border-hair/60 bg-ink-900/50 p-2 text-[11px] text-zinc-300">
        {JSON.stringify(value, null, 2)}
      </pre>
    </div>
  )
}
