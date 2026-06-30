import { lazy, Suspense, useCallback, useEffect, useRef, useState } from 'react'
import { api, type Drawing, type DrawingMeta } from '../api'
import { Button, Empty, PageHeader } from '../components/ui'
import '@excalidraw/excalidraw/index.css'

// Excalidraw is heavy; load it only when the Canvas page is opened.
const Excalidraw = lazy(() =>
  import('@excalidraw/excalidraw').then((m) => ({ default: m.Excalidraw })),
)

export function Canvas() {
  const [list, setList] = useState<DrawingMeta[]>([])
  const [current, setCurrent] = useState<Drawing | null>(null)
  const [saving, setSaving] = useState(false)
  const sceneRef = useRef<{ elements: readonly unknown[]; appState: Record<string, unknown> }>({
    elements: [],
    appState: {},
  })
  // Refs so the autosave/unmount-flush always see the latest open drawing and
  // whether there are unsaved edits, without stale closures.
  const currentRef = useRef<Drawing | null>(null)
  currentRef.current = current
  const dirtyRef = useRef(false)
  const autosaveTimer = useRef<ReturnType<typeof setTimeout> | null>(null)

  const loadList = useCallback(async () => {
    const { drawings } = await api.drawings()
    setList(drawings)
  }, [])

  useEffect(() => {
    void loadList()
  }, [loadList])

  // Bare persist (no React state) — safe to call from the unmount cleanup.
  // Only writes when there are unsaved edits.
  const persist = useCallback(async () => {
    const cur = currentRef.current
    if (!cur || !dirtyRef.current) return
    const appState = sceneRef.current.appState as any
    const clean = {
      viewBackgroundColor: appState?.viewBackgroundColor,
      theme: appState?.theme ?? 'dark', // remember the operator's theme choice
    }
    dirtyRef.current = false
    try {
      await api.updateDrawing(cur.id, { elements: sceneRef.current.elements, appState: clean })
    } catch {
      dirtyRef.current = true // keep dirty so a later flush retries
    }
  }, [])

  function scheduleAutosave() {
    dirtyRef.current = true
    if (autosaveTimer.current) clearTimeout(autosaveTimer.current)
    autosaveTimer.current = setTimeout(() => void persist(), 1500)
  }

  // Flush unsaved work when the Canvas page unmounts (e.g. switching tabs).
  useEffect(() => {
    return () => {
      if (autosaveTimer.current) clearTimeout(autosaveTimer.current)
      void persist()
    }
  }, [persist])

  async function open(id: number) {
    await persist() // don't lose edits to the currently-open drawing
    const { drawing } = await api.drawing(id)
    // Seed the scene ref so a Save before any onChange writes THIS drawing's
    // scene, not the previously-open one.
    sceneRef.current = {
      elements: drawing.data?.elements ?? [],
      appState: drawing.data?.appState ?? {},
    }
    dirtyRef.current = false
    setCurrent(drawing)
  }

  async function create() {
    await persist()
    const { drawing } = await api.createDrawing('Untitled', { elements: [], appState: { theme: 'dark' } })
    sceneRef.current = { elements: [], appState: {} }
    dirtyRef.current = false
    await loadList()
    setCurrent(drawing)
  }

  async function save() {
    if (!current) return
    setSaving(true)
    try {
      dirtyRef.current = true // force a write even if no onChange fired
      await persist()
      await loadList()
    } finally {
      setSaving(false)
    }
  }

  async function remove(id: number) {
    if (!confirm('Delete this drawing?')) return
    await api.deleteDrawing(id)
    if (current?.id === id) setCurrent(null)
    await loadList()
  }

  return (
    <div className="flex h-[calc(100vh-3rem)] flex-col">
      <PageHeader
        title="Canvas"
        subtitle="Excalidraw board — auto-saves as you draw and when you leave"
        actions={
          <>
            <Button variant="ghost" onClick={create}>
              New
            </Button>
            {current && (
              <Button onClick={save} disabled={saving}>
                {saving ? 'Saving…' : 'Save'}
              </Button>
            )}
          </>
        }
      />

      <div className="flex flex-1 gap-3 overflow-hidden">
        <aside className="w-48 shrink-0 space-y-1 overflow-auto">
          {list.length === 0 && <Empty>No drawings.</Empty>}
          {list.map((d) => (
            <div
              key={d.id}
              className={`flex items-center justify-between rounded-lg border px-2 py-1.5 text-sm ${
                current?.id === d.id ? 'border-zinc-600 bg-zinc-800' : 'border-hair hover:bg-ink-800/60'
              }`}
            >
              <button onClick={() => open(d.id)} className="flex-1 truncate text-left text-zinc-200">
                {d.name || 'Untitled'}
              </button>
              <button onClick={() => remove(d.id)} className="ml-2 text-xs text-red-400 hover:text-red-300">
                ✕
              </button>
            </div>
          ))}
        </aside>

        <div className="flex-1 overflow-hidden rounded-xl border border-hair bg-ink-950">
          {current ? (
            <Suspense fallback={<div className="p-6 text-sm text-zinc-500">Loading canvas…</div>}>
              <Excalidraw
                key={current.id}
                initialData={{
                  elements: (current.data?.elements ?? []) as never,
                  // Default to dark mode; keep a saved theme if the drawing has one.
                  appState: {
                    ...(current.data?.appState ?? {}),
                    theme: current.data?.appState?.theme ?? 'dark',
                  } as never,
                  scrollToContent: true,
                }}
                onChange={(elements, appState) => {
                  sceneRef.current = { elements, appState: appState as unknown as Record<string, unknown> }
                  scheduleAutosave()
                }}
              />
            </Suspense>
          ) : (
            <div className="flex h-full items-center justify-center text-sm text-zinc-400">
              Select or create a drawing.
            </div>
          )}
        </div>
      </div>
    </div>
  )
}
