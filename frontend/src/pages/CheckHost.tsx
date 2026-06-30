import { useState, type FormEvent } from 'react'
import { ApiError, api, type CheckHostResult } from '../api'
import { Badge, Button, Card, Empty, PageHeader } from '../components/ui'

function SectionTitle({ children }: { children: string }) {
  return <h2 className="mb-2 text-sm font-semibold text-zinc-200">{children}</h2>
}

function PingCard({ ping }: { ping: CheckHostResult['ping'] }) {
  return (
    <Card>
      <SectionTitle>Ping (ICMP)</SectionTitle>
      {!ping.available ? (
        <p className="text-xs text-zinc-500">ICMP ping is not available on the server.</p>
      ) : (
        <div className="space-y-2">
          <div className="flex items-center gap-2">
            <Badge tone={ping.alive ? 'green' : 'red'}>{ping.alive ? 'alive' : 'no reply'}</Badge>
            {ping.lossPct != null && <span className="text-xs text-zinc-500">{ping.lossPct}% loss</span>}
            {ping.transmitted != null && (
              <span className="text-xs text-zinc-500">
                {ping.received}/{ping.transmitted} packets
              </span>
            )}
          </div>
          {ping.rttMs && (
            <div className="font-mono text-xs text-zinc-400">
              rtt min/avg/max = {ping.rttMs.min}/{ping.rttMs.avg}/{ping.rttMs.max} ms
            </div>
          )}
          {ping.error && !ping.alive && <p className="text-xs text-zinc-600">{ping.error}</p>}
        </div>
      )}
    </Card>
  )
}

function TcpCard({ tcp }: { tcp: CheckHostResult['tcp'] }) {
  if (!tcp.length) return null
  return (
    <Card>
      <SectionTitle>TCP ports</SectionTitle>
      <div className="flex flex-wrap gap-2">
        {tcp.map((t) => (
          <div
            key={t.port}
            className={`flex items-center gap-2 rounded-lg border px-2.5 py-1 text-xs ${
              t.open ? 'border-green-900 bg-green-950/40' : 'border-zinc-800 bg-zinc-900/40'
            }`}
          >
            <span className="font-mono text-zinc-200">{t.port}</span>
            <span className={t.open ? 'text-green-400' : 'text-zinc-600'}>{t.open ? 'open' : 'closed'}</span>
            {t.open && t.latencyMs != null && <span className="text-zinc-500">{t.latencyMs}ms</span>}
          </div>
        ))}
      </div>
    </Card>
  )
}

function DnsHttpCard({ result }: { result: CheckHostResult }) {
  const dns = result.dns
  const http = result.http
  return (
    <Card>
      <SectionTitle>Resolution & HTTP</SectionTitle>
      <div className="space-y-1 text-xs">
        {result.resolvedIp && (
          <div className="flex gap-2">
            <span className="w-16 shrink-0 uppercase text-zinc-500">IP</span>
            <span className="font-mono text-zinc-300">{result.resolvedIp}</span>
          </div>
        )}
        {'error' in dns ? (
          <p className="text-red-400">{dns.error}</p>
        ) : (
          <>
            {dns.a.length > 0 && (
              <div className="flex gap-2">
                <span className="w-16 shrink-0 uppercase text-zinc-500">A</span>
                <span className="font-mono break-all text-zinc-300">{dns.a.join(', ')}</span>
              </div>
            )}
            {dns.aaaa.length > 0 && (
              <div className="flex gap-2">
                <span className="w-16 shrink-0 uppercase text-zinc-500">AAAA</span>
                <span className="font-mono break-all text-zinc-300">{dns.aaaa.join(', ')}</span>
              </div>
            )}
            {dns.cname.length > 0 && (
              <div className="flex gap-2">
                <span className="w-16 shrink-0 uppercase text-zinc-500">CNAME</span>
                <span className="font-mono break-all text-zinc-300">{dns.cname.join(', ')}</span>
              </div>
            )}
          </>
        )}
        {http && http.status != null && (
          <div className="flex items-center gap-2 pt-1">
            <span className="w-16 shrink-0 uppercase text-zinc-500">HTTP</span>
            <Badge tone={http.status < 400 ? 'green' : http.status < 500 ? 'amber' : 'red'}>{http.status}</Badge>
            {http.scheme && <span className="text-zinc-500">{http.scheme}</span>}
            {http.server && <span className="text-zinc-500">{http.server}</span>}
            {http.title && <span className="truncate text-zinc-400">{http.title}</span>}
          </div>
        )}
      </div>
    </Card>
  )
}

export function CheckHost() {
  const [host, setHost] = useState('')
  const [result, setResult] = useState<CheckHostResult | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [loading, setLoading] = useState(false)

  async function check(e: FormEvent) {
    e.preventDefault()
    const h = host.trim()
    if (!h || loading) return
    setLoading(true)
    setError(null)
    try {
      const { result } = await api.checkHost(h)
      setResult(result)
    } catch (err) {
      setResult(null)
      setError(err instanceof ApiError ? err.message : 'host check failed')
    } finally {
      setLoading(false)
    }
  }

  return (
    <div>
      <PageHeader title="Check Host" subtitle="Ping, TCP port and HTTP reachability for any host or IP" />

      <form onSubmit={check} className="mb-4 flex flex-wrap gap-2">
        <input
          value={host}
          onChange={(e) => setHost(e.target.value)}
          placeholder="example.com or 1.1.1.1"
          autoFocus
          spellCheck={false}
          className="min-w-0 flex-1 rounded-lg border border-zinc-700 bg-zinc-950 px-3 py-1.5 text-sm font-mono"
        />
        <Button type="submit" variant="loud" disabled={loading || !host.trim()}>
          {loading ? 'Checking…' : 'Check'}
        </Button>
      </form>

      {error && <Empty>{error}</Empty>}

      {result && !error && (
        <div className="space-y-3">
          <div className="text-xs text-zinc-500">
            {result.target}
            {result.resolvedIp && result.resolvedIp !== result.target ? ` → ${result.resolvedIp}` : ''}
          </div>
          <PingCard ping={result.ping} />
          <TcpCard tcp={result.tcp} />
          <DnsHttpCard result={result} />
        </div>
      )}

      {!result && !error && !loading && <Empty>Enter a host or IP to check its reachability.</Empty>}
    </div>
  )
}
