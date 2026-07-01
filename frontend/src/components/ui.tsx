import type { ButtonHTMLAttributes, ReactNode } from 'react'

export function Button({
  variant = 'default',
  className = '',
  ...props
}: ButtonHTMLAttributes<HTMLButtonElement> & {
  variant?: 'default' | 'ghost' | 'danger' | 'loud' | 'primary'
}) {
  const base =
    'inline-flex items-center justify-center gap-1.5 rounded-lg px-3 py-1.5 text-sm font-medium transition active:scale-[0.98] disabled:opacity-40 disabled:cursor-not-allowed disabled:active:scale-100'
  const variants: Record<string, string> = {
    // Neutral elevated button — secondary primary actions.
    default: 'bg-ink-800 text-zinc-100 border border-hair hover:bg-ink-700 hover:border-hair-strong',
    ghost: 'border border-hair text-zinc-300 hover:bg-ink-800 hover:border-hair-strong',
    danger: 'border border-red-900/70 text-red-300 hover:bg-red-950/50 hover:border-red-800',
    // Indigo brand action — the loud/primary CTA used across pages.
    loud: 'bg-accent-500 text-white shadow-sm shadow-accent-500/20 hover:bg-accent-400',
    primary: 'bg-accent-500 text-white shadow-sm shadow-accent-500/20 hover:bg-accent-400',
  }
  return <button className={`${base} ${variants[variant]} ${className}`} {...props} />
}

export function Card({ children, className = '' }: { children: ReactNode; className?: string }) {
  return (
    <div className={`rounded-xl border border-hair bg-ink-850 p-4 shadow-card ${className}`}>{children}</div>
  )
}

const BADGE_TONES: Record<string, string> = {
  zinc: 'bg-ink-700 text-zinc-300',
  green: 'bg-green-500/15 text-green-300 ring-1 ring-inset ring-green-500/20',
  amber: 'bg-amber-500/15 text-amber-300 ring-1 ring-inset ring-amber-500/20',
  red: 'bg-red-500/15 text-red-300 ring-1 ring-inset ring-red-500/20',
  blue: 'bg-blue-500/15 text-blue-300 ring-1 ring-inset ring-blue-500/20',
  indigo: 'bg-accent-500/15 text-accent-fg ring-1 ring-inset ring-accent-500/25',
  purple: 'bg-purple-500/15 text-purple-300 ring-1 ring-inset ring-purple-500/20',
}

export function Badge({
  children,
  tone = 'zinc',
}: {
  children: ReactNode
  tone?: 'zinc' | 'green' | 'amber' | 'red' | 'blue' | 'indigo' | 'purple'
}) {
  return <span className={`inline-flex items-center rounded-full px-2 py-0.5 text-xs ${BADGE_TONES[tone]}`}>{children}</span>
}

export function ScoreBadge({ score }: { score: number | null }) {
  if (score == null) return <Badge>—</Badge>
  const tone = score >= 70 ? 'red' : score >= 40 ? 'amber' : score >= 20 ? 'blue' : 'zinc'
  return <Badge tone={tone}>{score}</Badge>
}

export function JobStatusBadge({ status }: { status: string }) {
  const tone =
    status === 'done'
      ? 'green'
      : status === 'error' || status === 'dead'
        ? 'red'
        : status === 'running'
          ? 'amber'
          : 'zinc'
  return <Badge tone={tone}>{status}</Badge>
}

export function Empty({ children }: { children: ReactNode }) {
  return (
    <div className="rounded-xl border border-dashed border-hair bg-ink-900/60 p-8 text-sm text-zinc-400">
      {children}
    </div>
  )
}

export function Spinner() {
  return <span className="inline-block h-3 w-3 animate-pulse rounded-full bg-accent-500" />
}

// Download links for an export endpoint. Plain anchors so the browser handles
// the download (the session cookie is sent on the same-origin GET). Params are
// encoded via URLSearchParams so callers can't produce a malformed/injected URL.
export function ExportLinks({
  path,
  params = {},
  formats,
}: {
  path: string
  params?: Record<string, string | number | undefined>
  formats: string[]
}) {
  function href(format: string): string {
    const qs = new URLSearchParams()
    for (const [k, v] of Object.entries(params)) {
      if (v !== undefined && v !== '') qs.set(k, String(v))
    }
    qs.set('format', format)
    return `/api${path}?${qs.toString()}`
  }
  return (
    <div className="flex items-center gap-1.5">
      <span className="text-xs text-zinc-500">Export</span>
      {formats.map((f) => (
        <a
          key={f}
          href={href(f)}
          className="rounded-lg border border-hair px-2 py-1 text-xs text-zinc-300 transition hover:bg-ink-800 hover:border-hair-strong"
        >
          {f.toUpperCase()}
        </a>
      ))}
    </div>
  )
}

export function PageHeader({ title, subtitle, actions }: { title: string; subtitle?: string; actions?: ReactNode }) {
  return (
    <div className="mb-5 flex flex-wrap items-center justify-between gap-3">
      <div>
        <h1 className="text-xl font-semibold tracking-tight text-zinc-50">{title}</h1>
        {subtitle && <p className="mt-0.5 text-sm text-zinc-400">{subtitle}</p>}
      </div>
      {actions && <div className="flex flex-wrap gap-2">{actions}</div>}
    </div>
  )
}
