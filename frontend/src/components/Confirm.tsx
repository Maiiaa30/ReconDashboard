import { createContext, useCallback, useContext, useEffect, useId, useRef, useState, type ReactNode } from 'react'
import { AlertTriangle } from 'lucide-react'

// In-app confirmation dialog to replace window.confirm/alert — themed, keyboard
// friendly, and promise-based so call sites read like the old confirm():
//   if (!(await confirm({ message: '…', tone: 'danger' }))) return
interface ConfirmOptions {
  title?: string
  message: ReactNode
  confirmLabel?: string
  cancelLabel?: string
  tone?: 'default' | 'danger'
}
type ConfirmFn = (o: ConfirmOptions) => Promise<boolean>

const Ctx = createContext<ConfirmFn | null>(null)

export function ConfirmProvider({ children }: { children: ReactNode }) {
  const [dialog, setDialog] = useState<ConfirmOptions | null>(null)
  const resolver = useRef<((v: boolean) => void) | null>(null)
  const confirmBtn = useRef<HTMLButtonElement>(null)
  const panel = useRef<HTMLDivElement>(null)
  // The element focused before the dialog opened, so focus can be restored to it.
  const restoreFocus = useRef<HTMLElement | null>(null)
  const titleId = useId()
  const descId = useId()

  const confirm = useCallback<ConfirmFn>((o) => {
    // If a dialog is somehow already open, resolve its promise false rather than
    // leaking a forever-pending await when we overwrite the resolver.
    resolver.current?.(false)
    setDialog(o)
    return new Promise<boolean>((resolve) => {
      resolver.current = resolve
    })
  }, [])

  const close = useCallback((v: boolean) => {
    setDialog(null)
    resolver.current?.(v)
    resolver.current = null
  }, [])

  // While open: Esc cancels, the confirm button is auto-focused (Enter/Space
  // activates it), Tab is trapped inside the dialog, and on close focus returns
  // to whatever had it before — the keyboard baseline expected of a modal.
  useEffect(() => {
    if (!dialog) return
    restoreFocus.current = (document.activeElement as HTMLElement | null) ?? null
    confirmBtn.current?.focus()
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') {
        e.preventDefault()
        close(false)
        return
      }
      if (e.key === 'Tab') {
        const nodes = panel.current?.querySelectorAll<HTMLElement>(
          'button, [href], input, select, textarea, [tabindex]:not([tabindex="-1"])',
        )
        if (!nodes || nodes.length === 0) return
        const first = nodes[0]
        const last = nodes[nodes.length - 1]
        const active = document.activeElement
        if (e.shiftKey && (active === first || !panel.current?.contains(active))) {
          e.preventDefault()
          last.focus()
        } else if (!e.shiftKey && active === last) {
          e.preventDefault()
          first.focus()
        }
      }
    }
    window.addEventListener('keydown', onKey)
    return () => {
      window.removeEventListener('keydown', onKey)
      restoreFocus.current?.focus?.()
    }
  }, [dialog, close])

  const danger = dialog?.tone === 'danger'

  return (
    <Ctx.Provider value={confirm}>
      {children}
      {dialog && (
        <div className="fixed inset-0 z-[70] flex items-center justify-center p-4">
          <div className="absolute inset-0 bg-black/60 backdrop-blur-sm" onClick={() => close(false)} />
          <div
            ref={panel}
            role="alertdialog"
            aria-modal="true"
            aria-labelledby={dialog.title ? titleId : undefined}
            aria-describedby={descId}
            className="relative w-full max-w-sm rounded-2xl border border-hair bg-ink-850 p-5 shadow-pop"
          >
            <div className="flex items-start gap-3">
              {danger && (
                <span className="mt-0.5 flex h-8 w-8 shrink-0 items-center justify-center rounded-lg bg-red-500/15 text-red-400">
                  <AlertTriangle size={18} />
                </span>
              )}
              <div className="min-w-0">
                {dialog.title && <h2 id={titleId} className="text-base font-semibold text-zinc-100">{dialog.title}</h2>}
                <div id={descId} className="mt-1 whitespace-pre-wrap text-sm leading-relaxed text-zinc-300">{dialog.message}</div>
              </div>
            </div>
            <div className="mt-5 flex justify-end gap-2">
              <button
                onClick={() => close(false)}
                className="rounded-lg border border-hair px-3 py-1.5 text-sm text-zinc-300 transition hover:bg-ink-800 hover:border-hair-strong"
              >
                {dialog.cancelLabel ?? 'Cancel'}
              </button>
              <button
                ref={confirmBtn}
                onClick={() => close(true)}
                className={`rounded-lg px-3 py-1.5 text-sm font-medium text-white shadow-sm transition ${
                  danger ? 'bg-red-600 hover:bg-red-500 shadow-red-600/20' : 'bg-accent-500 hover:bg-accent-400 shadow-accent-500/20'
                }`}
              >
                {dialog.confirmLabel ?? 'Confirm'}
              </button>
            </div>
          </div>
        </div>
      )}
    </Ctx.Provider>
  )
}

export function useConfirm(): ConfirmFn {
  const ctx = useContext(Ctx)
  if (!ctx) throw new Error('useConfirm must be used within ConfirmProvider')
  return ctx
}
