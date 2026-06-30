import { useState } from 'react'
import type { Finding, Job } from '../api'
import { api } from '../api'
import { useApp, usePoll } from '../state'
import { Badge, Button, Card, Empty, PageHeader } from '../components/ui'

interface MxRecord {
  exchange: string
  priority: number
}

interface DnsData {
  a: string[]
  aaaa: string[]
  cname: string[]
  mx: MxRecord[]
  ns: string[]
  txt: string[]
}

interface WhoisData {
  server: string
  raw: string
}

interface CrtshData {
  count: number
  sample: string[]
  source?: string
}

interface InternetDbData {
  ip: string
  ports: number[]
  cpes: string[]
  hostnames: string[]
  vulns: string[]
}

interface ErrorField {
  error: string
}

interface TechData {
  url: string | null
  scheme: string | null
  status: number | null
  os: string | null
  server: string | null
  poweredBy: string | null
  cdn: string | null
  technologies: string[]
  headers: Record<string, string>
}

interface WaybackData {
  count: number
  sample: string[]
  withParams: string[]
}

interface OsintData {
  domain: string
  dns?: DnsData | ErrorField
  tech?: TechData | ErrorField
  whois?: WhoisData | ErrorField
  crtsh?: CrtshData | ErrorField
  wayback?: WaybackData | ErrorField
  internetdb?: InternetDbData | ErrorField | null
}

function isError(x: unknown): x is ErrorField {
  return !!x && typeof x === 'object' && 'error' in x && typeof (x as ErrorField).error === 'string'
}

function SectionTitle({ children }: { children: string }) {
  return <h2 className="mb-2 text-sm font-semibold text-zinc-200">{children}</h2>
}

function ErrorLine({ message }: { message: string }) {
  return <p className="text-xs text-red-400">{message}</p>
}

function DnsRow({ label, values }: { label: string; values: string[] }) {
  if (!values || values.length === 0) return null
  return (
    <div className="flex gap-2 text-xs">
      <span className="w-12 shrink-0 uppercase text-zinc-500">{label}</span>
      <span className="font-mono break-all text-zinc-300">{values.join(', ')}</span>
    </div>
  )
}

function DnsCard({ dns }: { dns: DnsData | ErrorField | undefined }) {
  if (!dns) return null
  return (
    <Card>
      <SectionTitle>DNS</SectionTitle>
      {isError(dns) ? (
        <ErrorLine message={dns.error} />
      ) : (
        <div className="space-y-1">
          <DnsRow label="A" values={dns.a} />
          <DnsRow label="AAAA" values={dns.aaaa} />
          <DnsRow label="CNAME" values={dns.cname} />
          <DnsRow label="MX" values={dns.mx?.map((m) => `${m.exchange} (${m.priority})`)} />
          <DnsRow label="NS" values={dns.ns} />
          <DnsRow label="TXT" values={dns.txt} />
        </div>
      )}
    </Card>
  )
}

function TechRow({ label, value }: { label: string; value: string | null | undefined }) {
  if (!value) return null
  return (
    <div className="flex gap-2 text-xs">
      <span className="w-16 shrink-0 uppercase text-zinc-500">{label}</span>
      <span className="font-mono break-all text-zinc-300">{value}</span>
    </div>
  )
}

function TechCard({ tech }: { tech: TechData | ErrorField | undefined }) {
  if (!tech) return null
  return (
    <Card>
      <SectionTitle>Server & technologies</SectionTitle>
      {isError(tech) ? (
        <ErrorLine message={tech.error} />
      ) : (
        <div className="space-y-3">
          <div className="space-y-1">
            <TechRow label="OS" value={tech.os} />
            <TechRow label="Server" value={tech.server} />
            <TechRow label="Powered by" value={tech.poweredBy} />
            <TechRow label="CDN" value={tech.cdn} />
            {tech.status != null && <TechRow label="HTTP" value={`${tech.status}${tech.scheme ? ` (${tech.scheme})` : ''}`} />}
          </div>
          {tech.technologies?.length > 0 && (
            <div>
              <div className="mb-1 text-xs uppercase tracking-wide text-zinc-500">Stack</div>
              <div className="flex flex-wrap gap-1">
                {tech.technologies.map((t) => (
                  <Badge key={t} tone="indigo">{t}</Badge>
                ))}
              </div>
            </div>
          )}
          {tech.headers && Object.keys(tech.headers).length > 0 && (
            <div>
              <div className="mb-1 text-xs uppercase tracking-wide text-zinc-500">Headers</div>
              <div className="space-y-0.5 font-mono text-xs text-zinc-500">
                {Object.entries(tech.headers).map(([k, v]) => (
                  <div key={k} className="break-all">
                    <span className="text-zinc-400">{k}:</span> {v}
                  </div>
                ))}
              </div>
            </div>
          )}
          {!tech.os && !tech.server && (!tech.technologies || tech.technologies.length === 0) && (
            <p className="text-xs text-zinc-500">No technology signals detected.</p>
          )}
        </div>
      )}
    </Card>
  )
}

function WhoisCard({ whois }: { whois: WhoisData | ErrorField | undefined }) {
  if (!whois) return null
  return (
    <Card>
      <SectionTitle>WHOIS</SectionTitle>
      {isError(whois) ? (
        <ErrorLine message={whois.error} />
      ) : (
        <div className="space-y-2">
          {whois.server && <div className="font-mono text-xs text-zinc-400">server: {whois.server}</div>}
          {whois.raw && (
            <pre className="max-h-80 overflow-auto whitespace-pre-wrap break-all text-xs text-zinc-400">
              {whois.raw}
            </pre>
          )}
        </div>
      )}
    </Card>
  )
}

function CrtshCard({ crtsh }: { crtsh: CrtshData | ErrorField | undefined }) {
  if (!crtsh) return null
  return (
    <Card>
      <SectionTitle>Certificate transparency</SectionTitle>
      {isError(crtsh) ? (
        <ErrorLine message={crtsh.error} />
      ) : (
        <div className="space-y-2">
          <div className="text-xs text-zinc-500">
            {crtsh.count} subdomains{crtsh.source ? ` · via ${crtsh.source}` : ''}
          </div>
          {crtsh.sample?.length > 0 && (
            <div className="space-y-0.5 font-mono text-xs text-zinc-300">
              {crtsh.sample.map((s) => (
                <div key={s} className="break-all">{s}</div>
              ))}
            </div>
          )}
        </div>
      )}
    </Card>
  )
}

function WaybackCard({ wb }: { wb: WaybackData | ErrorField | undefined }) {
  if (!wb) return null
  return (
    <Card>
      <SectionTitle>Wayback URLs</SectionTitle>
      {isError(wb) ? (
        <ErrorLine message={wb.error} />
      ) : (
        <div className="space-y-2">
          <div className="text-xs text-zinc-500">
            {wb.count} archived URL(s) · {wb.withParams.length} with parameters
          </div>
          {wb.withParams.length > 0 && (
            <div>
              <div className="mb-1 text-xs uppercase tracking-wide text-zinc-500">URLs with parameters (testable)</div>
              <div className="max-h-64 space-y-0.5 overflow-auto font-mono text-xs text-zinc-300">
                {wb.withParams.map((u) => (
                  <div key={u} className="break-all">{u}</div>
                ))}
              </div>
            </div>
          )}
          {wb.withParams.length === 0 && wb.sample.length > 0 && (
            <div className="max-h-48 space-y-0.5 overflow-auto font-mono text-xs text-zinc-400">
              {wb.sample.map((u) => (
                <div key={u} className="break-all">{u}</div>
              ))}
            </div>
          )}
        </div>
      )}
    </Card>
  )
}

function InternetDbCard({ idb }: { idb: InternetDbData | ErrorField | null | undefined }) {
  if (!idb) return null
  return (
    <Card>
      <SectionTitle>InternetDB</SectionTitle>
      {isError(idb) ? (
        <ErrorLine message={idb.error} />
      ) : (
        <div className="space-y-3">
          {idb.ip && <div className="font-mono text-xs text-zinc-400">{idb.ip}</div>}
          {idb.ports?.length > 0 && (
            <div>
              <div className="mb-1 text-xs uppercase tracking-wide text-zinc-500">Ports</div>
              <div className="flex flex-wrap gap-1">
                {idb.ports.map((p) => (
                  <Badge key={p} tone="blue">{p}</Badge>
                ))}
              </div>
            </div>
          )}
          {idb.cpes?.length > 0 && (
            <div>
              <div className="mb-1 text-xs uppercase tracking-wide text-zinc-500">CPEs</div>
              <div className="space-y-0.5 font-mono text-xs text-zinc-500">
                {idb.cpes.map((c) => (
                  <div key={c}>{c}</div>
                ))}
              </div>
            </div>
          )}
          {idb.vulns?.length > 0 && (
            <div>
              <div className="mb-1 text-xs uppercase tracking-wide text-zinc-500">Vulns</div>
              <div className="flex flex-wrap gap-1">
                {idb.vulns.map((v) => (
                  <Badge key={v} tone="red">{v}</Badge>
                ))}
              </div>
            </div>
          )}
        </div>
      )}
    </Card>
  )
}

export function Osint() {
  const { selected } = useApp()
  const [finding, setFinding] = useState<Finding | null>(null)
  const [jobId, setJobId] = useState<number | null>(null)
  const [running, setRunning] = useState(false)

  usePoll(
    () => {
      if (!selected) return
      api
        .findings({ domainId: selected.id, type: 'osint', limit: 1 })
        .then((r) => setFinding(r.findings[0] ?? null))
        .catch(() => {})
      if (jobId != null) {
        api
          .job(jobId)
          .then((r) => {
            const job: Job = r.job
            if (job.status === 'done' || job.status === 'error') {
              setRunning(false)
              setJobId(null)
            }
          })
          .catch(() => {
            setRunning(false)
            setJobId(null)
          })
      }
    },
    3000,
    !!selected,
  )

  if (!selected) return <Empty>Select a domain to view OSINT.</Empty>

  const gather = async () => {
    setRunning(true)
    try {
      const { jobId } = await api.osint(selected.id)
      setJobId(jobId)
    } catch {
      setRunning(false)
    }
  }

  const data = finding?.data as OsintData | undefined

  return (
    <div>
      <PageHeader
        title="OSINT"
        subtitle={`${selected.host} — passive intel`}
        actions={
          <Button variant="loud" onClick={gather} disabled={running}>
            {running ? 'Gathering…' : 'Gather OSINT'}
          </Button>
        }
      />

      {!data ? (
        <Empty>No OSINT gathered yet.</Empty>
      ) : (
        <div className="space-y-3">
          {finding && (
            <div className="text-xs text-zinc-600">
              Gathered {new Date(finding.createdAt).toLocaleString()}
            </div>
          )}
          <DnsCard dns={data.dns} />
          <TechCard tech={data.tech} />
          <WhoisCard whois={data.whois} />
          <CrtshCard crtsh={data.crtsh} />
          <WaybackCard wb={data.wayback} />
          <InternetDbCard idb={data.internetdb} />
        </div>
      )}
    </div>
  )
}
