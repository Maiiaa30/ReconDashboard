import { useState, type FormEvent } from 'react'
import { ApiError, api, type WhoisResult } from '../api'
import { Badge, Button, Card, Empty, PageHeader } from '../components/ui'

export function Whois() {
  const [query, setQuery] = useState('')
  const [result, setResult] = useState<WhoisResult | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [loading, setLoading] = useState(false)

  async function lookup(e: FormEvent) {
    e.preventDefault()
    const q = query.trim()
    if (!q || loading) return
    setLoading(true)
    setError(null)
    try {
      const { result } = await api.whois(q)
      setResult(result)
    } catch (err) {
      setResult(null)
      setError(err instanceof ApiError ? err.message : 'lookup failed')
    } finally {
      setLoading(false)
    }
  }

  return (
    <div>
      <PageHeader title="WHOIS" subtitle="Registration lookup for any domain or IP" />

      <form onSubmit={lookup} className="mb-4 flex flex-wrap gap-2">
        <input
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          placeholder="example.com or 8.8.8.8"
          autoFocus
          spellCheck={false}
          className="min-w-0 flex-1 rounded-lg border border-zinc-700 bg-zinc-950 px-3 py-1.5 text-sm font-mono"
        />
        <Button type="submit" variant="loud" disabled={loading || !query.trim()}>
          {loading ? 'Looking up…' : 'Lookup'}
        </Button>
      </form>

      {error && <Empty>{error}</Empty>}

      {result && !error && (
        <Card>
          <div className="mb-2 flex flex-wrap items-center gap-2">
            <span className="font-mono text-sm text-zinc-200">{result.query}</span>
            <Badge tone={result.kind === 'ip' ? 'blue' : 'zinc'}>{result.kind}</Badge>
            <span className="text-xs text-zinc-500">via {result.server}</span>
          </div>
          <pre className="max-h-[28rem] overflow-auto whitespace-pre-wrap break-all rounded-lg bg-zinc-950/60 p-3 text-xs text-zinc-400">
            {result.raw || '(empty response)'}
          </pre>
        </Card>
      )}

      {!result && !error && !loading && <Empty>Enter a domain or IP to look up its WHOIS record.</Empty>}
    </div>
  )
}
