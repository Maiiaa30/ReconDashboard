import { useRef } from 'react'
import { api, type Job } from '../api'
import { usePoll } from '../state'
import { useToast } from './Toast'
import { summarizeJob } from '../lib/format'

// App-wide watcher: polls the job list and fires a toast (plus a best-effort
// desktop notification) whenever a job reaches a terminal state — so the
// operator learns a scan/tool finished without camping on the Logs page.

const LABEL: Record<string, string> = {
  subdomain_discovery: 'Subdomain discovery',
  exposure_scan: 'Exposure scan',
  osint_gather: 'OSINT gather',
  nmap_scan: 'nmap scan',
  nuclei_scan: 'nuclei scan',
  ffuf_scan: 'ffuf scan',
  screenshot: 'Screenshots',
  origin_scan: 'Origin discovery',
  owasp_active: 'OWASP checks',
  tool_scan: 'Tool scan',
  leak_check: 'Leak check',
}

const TERMINAL = new Set(['done', 'error', 'cancelled', 'dead'])

// A job that appeared after the initial prime and is already terminal counts as
// "just finished" if it wrapped up in the last ~20s — this catches fast jobs
// that go queued→done within a single poll interval.
function recentlyFinished(j: Job): boolean {
  if (!j.finishedAt) return true
  const t = new Date(j.finishedAt).getTime()
  return !Number.isFinite(t) || Date.now() - t < 20_000
}

function labelFor(j: Job): string {
  const base = LABEL[j.type] ?? j.type
  // tool_scan carries the specific tool in its params — surface it.
  const p = j.params
  if (j.type === 'tool_scan' && p && typeof p === 'object' && 'tool' in p) {
    const tool = (p as Record<string, unknown>).tool
    if (typeof tool === 'string' && tool) return `${tool} (tool)`
  }
  return base
}

function desktopNote(title: string, body?: string) {
  try {
    if ('Notification' in window && Notification.permission === 'granted') {
      new Notification(title, { body: body || undefined })
    }
  } catch {
    /* notifications unavailable — the toast already covered it */
  }
}

export function JobNotifier() {
  const toast = useToast()
  const seen = useRef<Map<number, string>>(new Map())
  const primed = useRef(false)

  usePoll(
    () => {
      api
        .jobs()
        .then(({ jobs }) => {
          // First pass primes the status map WITHOUT notifying, so opening the
          // app doesn't spray toasts for jobs that finished earlier.
          if (!primed.current) {
            for (const j of jobs) seen.current.set(j.id, j.status)
            primed.current = true
            return
          }
          for (const j of jobs) {
            const prev = seen.current.get(j.id)
            seen.current.set(j.id, j.status)
            // START notification: a job entering the running state (from queued,
            // or a brand-new job first caught running after the prime pass).
            if (j.status === 'running' && prev !== 'running') {
              toast.info(`${labelFor(j)} started`)
              continue
            }
            if (!TERMINAL.has(j.status)) continue
            // Fire on a real transition from a live state we saw, OR on a
            // brand-new job (enqueued after prime) that finished so fast we only
            // ever caught it terminal.
            const transitioned = prev !== undefined && !TERMINAL.has(prev)
            const freshlyDone = prev === undefined && recentlyFinished(j)
            if (!transitioned && !freshlyDone) continue

            const label = labelFor(j)
            if (j.status === 'done') {
              const s = summarizeJob(j.type, j.result)
              toast.success(`${label} finished${s ? ` — ${s}` : ''}`)
              desktopNote(`${label} finished`, s || undefined)
            } else if (j.status === 'cancelled') {
              toast.info(`${label} cancelled`)
            } else {
              const why = j.error ? ` — ${j.error.slice(0, 90)}` : ''
              toast.error(`${label} ${j.status === 'dead' ? 'died' : 'failed'}${why}`)
              desktopNote(`${label} failed`, j.error ?? undefined)
            }
          }
        })
        .catch(() => {})
    },
    4000,
    true,
  )

  return null
}
