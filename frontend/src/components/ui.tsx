import type { ButtonHTMLAttributes, ReactNode } from 'react'

export function Button({
  variant = 'default',
  className = '',
  ...props
}: ButtonHTMLAttributes<HTMLButtonElement> & { variant?: 'default' | 'ghost' | 'danger' | 'loud' }) {
  const base =
    'rounded-lg px-3 py-1.5 text-sm font-medium transition disabled:opacity-40 disabled:cursor-not-allowed'
  const variants: Record<string, string> = {
    default: 'bg-zinc-100 text-zinc-900 hover:bg-white',
    ghost: 'border border-zinc-700 text-zinc-300 hover:bg-zinc-800',
    danger: 'border border-red-900 text-red-300 hover:bg-red-950',
    loud: 'bg-amber-500 text-zinc-950 hover:bg-amber-400',
  }
  return <button className={`${base} ${variants[variant]} ${className}`} {...props} />
}

export function Card({ children, className = '' }: { children: ReactNode; className?: string }) {
  return (
    <div className={`rounded-xl border border-zinc-800 bg-zinc-900/40 p-4 ${className}`}>{children}</div>
  )
}

export function Badge({ children, tone = 'zinc' }: { children: ReactNode; tone?: 'zinc' | 'green' | 'amber' | 'red' | 'blue' }) {
  const tones: Record<string, string> = {
    zinc: 'bg-zinc-800 text-zinc-300',
    green: 'bg-green-900/50 text-green-300',
    amber: 'bg-amber-900/50 text-amber-300',
    red: 'bg-red-900/50 text-red-300',
    blue: 'bg-blue-900/50 text-blue-300',
  }
  return <span className={`rounded-full px-2 py-0.5 text-xs ${tones[tone]}`}>{children}</span>
}

export function ScoreBadge({ score }: { score: number | null }) {
  if (score == null) return <Badge>—</Badge>
  const tone = score >= 70 ? 'red' : score >= 40 ? 'amber' : score >= 20 ? 'blue' : 'zinc'
  return <Badge tone={tone}>{score}</Badge>
}

export function JobStatusBadge({ status }: { status: string }) {
  const tone = status === 'done' ? 'green' : status === 'error' ? 'red' : status === 'running' ? 'amber' : 'zinc'
  return <Badge tone={tone}>{status}</Badge>
}

export function Empty({ children }: { children: ReactNode }) {
  return (
    <div className="rounded-xl border border-dashed border-zinc-800 bg-zinc-900/30 p-8 text-sm text-zinc-500">
      {children}
    </div>
  )
}

export function Spinner() {
  return <span className="inline-block h-3 w-3 animate-pulse rounded-full bg-amber-500" />
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
          className="rounded-lg border border-zinc-700 px-2 py-1 text-xs text-zinc-300 hover:bg-zinc-800"
        >
          {f.toUpperCase()}
        </a>
      ))}
    </div>
  )
}

export function PageHeader({ title, subtitle, actions }: { title: string; subtitle?: string; actions?: ReactNode }) {
  return (
    <div className="mb-4 flex flex-wrap items-center justify-between gap-3">
      <div>
        <h1 className="text-lg font-semibold tracking-tight">{title}</h1>
        {subtitle && <p className="text-sm text-zinc-500">{subtitle}</p>}
      </div>
      {actions && <div className="flex flex-wrap gap-2">{actions}</div>}
    </div>
  )
}
