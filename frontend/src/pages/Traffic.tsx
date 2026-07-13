import { useState } from 'react'
import { Repeat, ChevronRight, Trash2 } from 'lucide-react'
import { api, type Capture } from '../api'
import { useApp, usePoll } from '../state'
import { Badge, Button, Card, Empty, PageHeader, SkeletonList } from '../components/ui'
import { useToast } from '../components/Toast'
import { useConfirm } from '../components/Confirm'
import { timeAgo } from '../lib/format'
import { setPendingReplay } from '../lib/replayHandoff'

const METHOD_TONE: Record<string, 'green' | 'blue' | 'amber' | 'red' | 'zinc'> = {
  GET: 'green',
  POST: 'blue',
  PUT: 'amber',
  PATCH: 'amber',
  DELETE: 'red',
}

function shortUrl(u: string): string {
  try {
    const x = new URL(u)
    return x.pathname + x.search
  } catch {
    return u
  }
}

export function Traffic({ navigate }: { navigate: (page: string, domainId?: number) => void }) {
  const { selected } = useApp()
  const toast = useToast()
  const ask = useConfirm()
  const [captures, setCaptures] = useState<Capture[]>([])
  const [loaded, setLoaded] = useState(false)

  usePoll(
    () => {
      if (!selected) return
      api
        .captures(selected.id, 300)
        .then((r) => setCaptures(r.captures))
        .catch(() => {})
        .finally(() => setLoaded(true))
    },
    4000,
    !!selected,
    selected?.id,
  )

  function sendToReplay(c: Capture) {
    setPendingReplay({ method: c.method, url: c.url, headers: c.headers, body: c.body })
    navigate('replay')
  }

  async function clearAll() {
    if (!selected) return
    const ok = await ask({
      title: 'Clear captured traffic?',
      message: `Delete all ${captures.length} captured request(s) for ${selected.host}. This can't be undone.`,
      confirmLabel: 'Clear',
      tone: 'danger',
    })
    if (!ok) return
    try {
      const { cleared } = await api.clearCaptures(selected.id)
      toast.success(`Cleared ${cleared} request(s).`)
      setCaptures([])
    } catch {
      toast.error('Failed to clear.')
    }
  }

  if (!selected) return <Empty>Select a domain to see captured traffic for it.</Empty>

  return (
    <div>
      <PageHeader
        title="Traffic"
        subtitle={`${selected.host} — requests captured by the browser extension, ready to replay`}
        actions={
          captures.length > 0 ? (
            <Button variant="ghost" onClick={clearAll}>
              <Trash2 size={15} /> Clear
            </Button>
          ) : undefined
        }
      />

      {!loaded ? (
        <SkeletonList rows={5} />
      ) : captures.length === 0 ? (
        <Empty>
          <div className="space-y-1.5">
            <div>No captured requests yet for this target.</div>
            <div className="text-xs leading-relaxed text-zinc-500">
              Traffic is fed by the <span className="text-zinc-300">capture browser extension</span>: install it, set your dashboard
              URL + the <span className="font-mono">CAPTURE_TOKEN</span>, turn it on, and browse the target. Requests to hosts within a
              tracked domain show up here — click <span className="text-zinc-300">Send to Replay</span> to open one in the Repeater.
            </div>
          </div>
        </Empty>
      ) : (
        <div className="space-y-2">
          {captures.map((c) => (
            <CaptureRow key={c.id} c={c} onSend={() => sendToReplay(c)} />
          ))}
        </div>
      )}
    </div>
  )
}

function CaptureRow({ c, onSend }: { c: Capture; onSend: () => void }) {
  const [open, setOpen] = useState(false)
  return (
    <Card>
      <div className="flex flex-wrap items-center gap-2">
        <Badge tone={METHOD_TONE[c.method] ?? 'zinc'}>{c.method}</Badge>
        <span className="font-mono text-xs text-zinc-500">{c.host}</span>
        <span className="min-w-0 flex-1 truncate font-mono text-sm text-zinc-200" title={c.url}>
          {shortUrl(c.url)}
        </span>
        <span className="text-[11px] text-zinc-600">{timeAgo(new Date(c.createdAt).getTime())}</span>
        <Button variant="ghost" onClick={onSend}>
          <Repeat size={14} /> Send to Replay
        </Button>
      </div>
      <button
        onClick={() => setOpen((v) => !v)}
        className="mt-1.5 inline-flex items-center gap-1 text-xs text-zinc-500 hover:text-zinc-300"
      >
        <ChevronRight size={12} className={open ? 'rotate-90 transition' : 'transition'} />
        {c.headers.length} header(s){c.body ? ' · has body' : ''}
      </button>
      {open && (
        <div className="mt-2 space-y-2">
          <pre className="max-h-40 overflow-auto rounded-lg border border-hair/60 bg-ink-900/50 p-2 font-mono text-[11px] text-zinc-300">
            {c.headers.map(([k, v]) => `${k}: ${v}`).join('\n') || '(no headers captured)'}
          </pre>
          {c.body && (
            <div>
              <div className="mb-1 text-[10px] uppercase tracking-wide text-zinc-600">Body</div>
              <pre className="max-h-40 overflow-auto rounded-lg border border-hair/60 bg-ink-900/50 p-2 font-mono text-[11px] text-zinc-300 whitespace-pre-wrap break-all">
                {c.body}
              </pre>
            </div>
          )}
        </div>
      )}
    </Card>
  )
}
