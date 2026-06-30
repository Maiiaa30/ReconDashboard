import { useState } from 'react'
import type { Finding, Job } from '../api'
import { api } from '../api'
import { useApp, usePoll } from '../state'
import { Badge, Button, Card, Empty, PageHeader, ScoreBadge } from '../components/ui'

interface Cve {
  cve_id: string
  summary?: string
  cvss?: number
}

interface ExposureData {
  ip: string
  host: string
  hostnames: string[]
  ports: number[]
  cpes: string[]
  tags: string[]
  vulns: string[]
  cves: Cve[]
}

function truncate(s: string, n = 160): string {
  return s.length > n ? `${s.slice(0, n)}…` : s
}

function ExposureCard({ finding }: { finding: Finding }) {
  const data = finding.data as ExposureData
  return (
    <Card>
      <div className="mb-3 flex flex-wrap items-center justify-between gap-2">
        <div className="font-mono text-sm text-zinc-200">
          {data.ip}
          {data.host && <span className="text-zinc-500"> — {data.host}</span>}
        </div>
        <ScoreBadge score={finding.score} />
      </div>

      {data.ports?.length > 0 && (
        <div className="mb-3">
          <div className="mb-1 text-xs uppercase tracking-wide text-zinc-500">Open ports</div>
          <div className="flex flex-wrap gap-1">
            {data.ports.map((p) => (
              <Badge key={p} tone="blue">{p}</Badge>
            ))}
          </div>
        </div>
      )}

      {data.cpes?.length > 0 && (
        <div className="mb-3">
          <div className="mb-1 text-xs uppercase tracking-wide text-zinc-500">CPEs</div>
          <div className="space-y-0.5 font-mono text-xs text-zinc-500">
            {data.cpes.map((c) => (
              <div key={c}>{c}</div>
            ))}
          </div>
        </div>
      )}

      {(data.cves?.length > 0 || data.vulns?.length > 0) && (
        <div className="mb-3">
          <div className="mb-1 text-xs uppercase tracking-wide text-zinc-500">Vulnerabilities</div>
          <div className="space-y-1.5">
            {data.cves?.map((cve) => (
              <div key={cve.cve_id} className="flex flex-wrap items-start gap-2">
                <Badge tone="red">{cve.cve_id}</Badge>
                {cve.cvss != null && <span className="text-xs text-zinc-500">CVSS {cve.cvss}</span>}
                {cve.summary && (
                  <span className="text-xs text-zinc-400">{truncate(cve.summary)}</span>
                )}
              </div>
            ))}
            {data.vulns
              ?.filter((v) => !data.cves?.some((c) => c.cve_id === v))
              .map((v) => (
                <div key={v}>
                  <Badge tone="red">{v}</Badge>
                </div>
              ))}
          </div>
        </div>
      )}

      {finding.tags?.length > 0 && (
        <div className="flex flex-wrap gap-1">
          {finding.tags.map((t) => (
            <Badge key={t}>{t}</Badge>
          ))}
        </div>
      )}

      <div className="mt-3 text-xs text-zinc-600">
        {new Date(finding.createdAt).toLocaleString()}
      </div>
    </Card>
  )
}

export function Exposure() {
  const { selected } = useApp()
  const [findings, setFindings] = useState<Finding[]>([])
  const [jobId, setJobId] = useState<number | null>(null)
  const [running, setRunning] = useState(false)

  usePoll(
    () => {
      if (!selected) return
      api
        .findings({ domainId: selected.id, type: 'exposure' })
        .then((r) => setFindings(r.findings))
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

  if (!selected) return <Empty>Select a domain to view exposure.</Empty>

  const runScan = async () => {
    setRunning(true)
    try {
      const { jobId } = await api.exposure(selected.id)
      setJobId(jobId)
    } catch {
      setRunning(false)
    }
  }

  return (
    <div>
      <PageHeader
        title="Exposure"
        subtitle={`${selected.host} — passive (Shodan InternetDB)`}
        actions={
          <Button variant="loud" onClick={runScan} disabled={running}>
            {running ? 'Scanning…' : 'Run exposure scan'}
          </Button>
        }
      />

      {findings.length === 0 ? (
        <Empty>No exposure data yet. Run a scan.</Empty>
      ) : (
        <div className="space-y-3">
          {findings.map((f) => (
            <ExposureCard key={f.id} finding={f} />
          ))}
        </div>
      )}
    </div>
  )
}
