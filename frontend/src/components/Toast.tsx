import { createContext, useCallback, useContext, useMemo, useRef, useState, type ReactNode } from 'react'
import { CheckCircle2, AlertTriangle, Info, X, type LucideIcon } from 'lucide-react'

// Lightweight toast layer — the app's async actions (triage writes, snapshots)
// previously failed silently via `.catch(() => {})`. This gives the operator a
// distinguishable success/error signal without pulling in a toast dependency.
type ToastKind = 'success' | 'error' | 'info'
interface Toast {
  id: number
  kind: ToastKind
  message: string
}

interface ToastApi {
  push: (kind: ToastKind, message: string) => void
  success: (message: string) => void
  error: (message: string) => void
  info: (message: string) => void
}

const Ctx = createContext<ToastApi | null>(null)

const STYLE: Record<ToastKind, { icon: LucideIcon; border: string; icon_: string }> = {
  success: { icon: CheckCircle2, border: 'border-green-500/40', icon_: 'text-green-400' },
  error: { icon: AlertTriangle, border: 'border-red-500/40', icon_: 'text-red-400' },
  info: { icon: Info, border: 'border-accent-500/40', icon_: 'text-accent-400' },
}

export function ToastProvider({ children }: { children: ReactNode }) {
  const [toasts, setToasts] = useState<Toast[]>([])
  const nextId = useRef(1)

  const dismiss = useCallback((id: number) => {
    setToasts((prev) => prev.filter((t) => t.id !== id))
  }, [])

  const push = useCallback(
    (kind: ToastKind, message: string) => {
      const id = nextId.current++
      setToasts((prev) => [...prev, { id, kind, message }])
      // Errors linger longer than confirmations — the operator may need to read them.
      window.setTimeout(() => dismiss(id), kind === 'error' ? 6000 : 3500)
    },
    [dismiss],
  )

  // Stable API object (push is stable) so consumers can safely list it in
  // useCallback/useEffect dependency arrays.
  const api = useMemo<ToastApi>(
    () => ({
      push,
      success: (m) => push('success', m),
      error: (m) => push('error', m),
      info: (m) => push('info', m),
    }),
    [push],
  )

  return (
    <Ctx.Provider value={api}>
      {children}
      <div className="pointer-events-none fixed inset-x-0 bottom-0 z-[60] flex flex-col items-center gap-2 p-4 sm:items-end">
        {toasts.map((t) => {
          const s = STYLE[t.kind]
          const Icon = s.icon
          return (
            <div
              key={t.id}
              role="status"
              className={`pointer-events-auto flex w-full max-w-sm items-start gap-2.5 rounded-xl border ${s.border} bg-ink-850 px-3.5 py-2.5 text-sm text-zinc-100 shadow-pop`}
            >
              <Icon size={16} className={`mt-0.5 shrink-0 ${s.icon_}`} />
              <span className="min-w-0 flex-1 break-words">{t.message}</span>
              <button
                onClick={() => dismiss(t.id)}
                aria-label="Dismiss"
                className="shrink-0 text-zinc-500 transition hover:text-zinc-200"
              >
                <X size={14} />
              </button>
            </div>
          )
        })}
      </div>
    </Ctx.Provider>
  )
}

export function useToast(): ToastApi {
  const ctx = useContext(Ctx)
  if (!ctx) throw new Error('useToast must be used within ToastProvider')
  return ctx
}
