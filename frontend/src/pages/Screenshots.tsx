import { useCallback, useEffect, useState } from 'react'
import { api, type MetaStatus, type ScreenshotEntry } from '../api'
import { useApp, usePoll } from '../state'
import { Badge, Button, Empty, PageHeader } from '../components/ui'
import { timeAgo } from '../lib/format'

function statusTone(status: number | null): 'green' | 'blue' | 'amber' | 'red' | 'zinc' {
  if (status == null) return 'zinc'
  if (status >= 200 && status < 300) return 'green'
  if (status >= 300 && status < 400) return 'blue'
  if (status === 401 || status === 403) return 'amber'
  if (status >= 400) return 'red'
  return 'zinc'
}

export function Screenshots() {
  const { selected } = useApp()
  const [shots, setShots] = useState<ScreenshotEntry[]>([])
  const [meta, setMeta] = useState<MetaStatus | null>(null)
  const [running, setRunning] = useState(false)
  const [lastJob, setLastJob] = useState<number | null>(null)
  const [failed, setFailed] = useState<Set<string>>(new Set())
  const [lightbox, setLightbox] = useState<ScreenshotEntry | null>(null)

  useEffect(() => {
    api.meta().then(setMeta).catch(() => setMeta(null))
  }, [])

  const load = useCallback(() => {
    if (!selected) return
    api.screenshots(selected.id).then((r) => setShots(r.screenshots)).catch(() => {})
    // Track the capture job so the button reflects real completion.
    if (lastJob != null) {
      api.job(lastJob).then((r) => {
        if (r.job.status === 'done' || r.job.status === 'error') {
          setRunning(false)
          setLastJob(null)
        }
      }).catch(() => {})
    }
  }, [selected, lastJob])
  usePoll(load, 4000, !!selected)

  // Lightbox: Escape to close + lock background scroll while open.
  useEffect(() => {
    if (!lightbox) return
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') setLightbox(null)
    }
    document.addEventListener('keydown', onKey)
    const prevOverflow = document.body.style.overflow
    document.body.style.overflow = 'hidden'
    return () => {
      document.removeEventListener('keydown', onKey)
      document.body.style.overflow = prevOverflow
    }
  }, [lightbox])

  if (!selected) return <Empty>Select a domain to view screenshots.</Empty>

  const chromiumMissing = meta ? !meta.tools.chromium : false

  async function capture() {
    if (!selected) return
    setRunning(true)
    try {
      const { jobId } = await api.captureScreenshots(selected.id)
      setLastJob(jobId) // cleared when the job reaches a terminal status
    } catch {
      setRunning(false)
    }
  }

  return (
    <div>
      <PageHeader
        title="Screenshots"
        subtitle={`${selected.host} — ${shots.length} captured`}
        actions={
          <Button onClick={capture} disabled={running || chromiumMissing}>
            {running ? 'Capturing…' : 'Capture live hosts'}
          </Button>
        }
      />

      {chromiumMissing && (
        <p className="mb-3 text-xs text-zinc-500">
          Chromium isn’t installed in this image, so screenshots are unavailable. (Runs in Docker.)
        </p>
      )}

      {shots.length === 0 ? (
        <Empty>
          No screenshots yet. Click “Capture live hosts” to screenshot every subdomain that responded to
          the HTTP probe. (Run discovery first so there are live hosts.)
        </Empty>
      ) : (
        <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-3">
          {shots.map((s) => (
            <button
              key={s.host}
              onClick={() => setLightbox(s)}
              className="group overflow-hidden rounded-xl border border-zinc-800 bg-zinc-900/40 text-left hover:border-zinc-600"
            >
              <div className="flex aspect-[16/10] items-center justify-center overflow-hidden bg-zinc-950">
                {failed.has(s.host) ? (
                  <span className="text-xs text-zinc-600">no preview</span>
                ) : (
                  <img
                    src={api.screenshotUrl(selected.id, s.host)}
                    alt={s.host}
                    loading="lazy"
                    onError={() => setFailed((prev) => new Set(prev).add(s.host))}
                    className="h-full w-full object-cover object-top transition group-hover:opacity-90"
                  />
                )}
              </div>
              <div className="flex items-center gap-2 p-2">
                <Badge tone={statusTone(s.status)}>{s.status ?? '—'}</Badge>
                <span className="min-w-0 flex-1 truncate font-mono text-xs text-zinc-200">{s.host}</span>
                <span className="shrink-0 text-[10px] text-zinc-600">{timeAgo(s.capturedAt ? new Date(s.capturedAt).getTime() : null)}</span>
              </div>
              {s.title && <div className="truncate px-2 pb-2 text-xs text-zinc-500">{s.title}</div>}
            </button>
          ))}
        </div>
      )}

      {lightbox && (
        <div
          onClick={() => setLightbox(null)}
          role="dialog"
          aria-modal="true"
          aria-label={`Screenshot of ${lightbox.host}`}
          className="fixed inset-0 z-50 flex flex-col items-center justify-center bg-black/80 p-6"
        >
          <div className="mb-2 flex w-full max-w-5xl items-center gap-2 text-sm">
            <Badge tone={statusTone(lightbox.status)}>{lightbox.status ?? '—'}</Badge>
            <span className="font-mono text-zinc-200">{lightbox.host}</span>
            {lightbox.scheme && (
              <a
                href={`${lightbox.scheme}://${lightbox.host}`}
                target="_blank"
                rel="noreferrer"
                onClick={(e) => e.stopPropagation()}
                className="text-sky-400 hover:underline"
              >
                open ↗
              </a>
            )}
            <button className="ml-auto text-zinc-400 hover:text-zinc-200" onClick={() => setLightbox(null)}>
              ✕ close
            </button>
          </div>
          <img
            src={api.screenshotUrl(selected.id, lightbox.host)}
            alt={lightbox.host}
            onClick={(e) => e.stopPropagation()}
            className="max-h-[80vh] max-w-5xl rounded-lg border border-zinc-700 object-contain"
          />
        </div>
      )}
    </div>
  )
}
