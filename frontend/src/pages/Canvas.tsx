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

  const loadList = useCallback(async () => {
    const { drawings } = await api.drawings()
    setList(drawings)
  }, [])

  useEffect(() => {
    void loadList()
  }, [loadList])

  async function open(id: number) {
    const { drawing } = await api.drawing(id)
    // Seed the scene ref so a Save before any onChange writes THIS drawing's
    // scene, not the previously-open one.
    sceneRef.current = {
      elements: drawing.data?.elements ?? [],
      appState: drawing.data?.appState ?? {},
    }
    setCurrent(drawing)
  }

  async function create() {
    const { drawing } = await api.createDrawing('Untitled', { elements: [], appState: {} })
    sceneRef.current = { elements: [], appState: {} }
    await loadList()
    setCurrent(drawing)
  }

  async function save() {
    if (!current) return
    setSaving(true)
    try {
      // Persist elements + a minimal appState (drop non-serializable bits).
      const appState = sceneRef.current.appState
      const clean = { viewBackgroundColor: (appState as any)?.viewBackgroundColor ?? '#ffffff' }
      await api.updateDrawing(current.id, {
        elements: sceneRef.current.elements,
        appState: clean,
      })
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
        subtitle="Excalidraw board, saved to the database"
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
                current?.id === d.id ? 'border-zinc-600 bg-zinc-800' : 'border-zinc-800 hover:bg-zinc-800/50'
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

        <div className="flex-1 overflow-hidden rounded-xl border border-zinc-800 bg-white">
          {current ? (
            <Suspense fallback={<div className="p-6 text-sm text-zinc-500">Loading canvas…</div>}>
              <Excalidraw
                key={current.id}
                initialData={{
                  elements: (current.data?.elements ?? []) as never,
                  appState: (current.data?.appState ?? {}) as never,
                  scrollToContent: true,
                }}
                onChange={(elements, appState) => {
                  sceneRef.current = { elements, appState: appState as unknown as Record<string, unknown> }
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
