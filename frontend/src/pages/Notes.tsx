import { useCallback, useEffect, useState } from 'react'
import { api, type Note } from '../api'
import { useApp } from '../state'
import { Button, Card, Empty, PageHeader } from '../components/ui'

export function Notes() {
  const { selected } = useApp()
  const [scope, setScope] = useState<'global' | 'domain'>('global')
  const [notes, setNotes] = useState<Note[]>([])
  const [editing, setEditing] = useState<Note | null>(null)
  const [title, setTitle] = useState('')
  const [body, setBody] = useState('')

  const scopeId: number | 'global' = scope === 'global' || !selected ? 'global' : selected.id

  const load = useCallback(async () => {
    const { notes } = await api.notes(scopeId)
    setNotes(notes)
  }, [scopeId])

  useEffect(() => {
    void load()
  }, [load])

  function startNew() {
    setEditing(null)
    setTitle('')
    setBody('')
  }

  function startEdit(n: Note) {
    setEditing(n)
    setTitle(n.title ?? '')
    setBody(n.body ?? '')
  }

  async function save() {
    try {
      if (editing) {
        await api.updateNote(editing.id, title, body)
      } else {
        const domainId = scope === 'domain' && selected ? selected.id : null
        await api.createNote(domainId, title, body)
      }
      startNew()
      await load()
    } catch (err) {
      alert(`Failed to save note: ${err instanceof Error ? err.message : 'error'}`)
    }
  }

  async function remove(id: number) {
    if (!confirm('Delete this note?')) return
    if (editing?.id === id) startNew()
    try {
      await api.deleteNote(id)
      await load()
    } catch (err) {
      alert(`Failed to delete note: ${err instanceof Error ? err.message : 'error'}`)
    }
  }

  return (
    <div>
      <PageHeader
        title="Notes"
        subtitle="Markdown notes, global or per-domain"
        actions={
          <select
            value={scope}
            onChange={(e) => setScope(e.target.value as 'global' | 'domain')}
            className="rounded-lg border border-zinc-700 bg-zinc-950 px-3 py-1.5 text-sm"
          >
            <option value="global">Global notes</option>
            <option value="domain" disabled={!selected}>
              {selected ? `Domain: ${selected.host}` : 'Domain (select one)'}
            </option>
          </select>
        }
      />

      <div className="grid gap-4 md:grid-cols-2">
        <div className="space-y-2">
          {notes.length === 0 ? (
            <Empty>No notes in this scope yet.</Empty>
          ) : (
            notes.map((n) => (
              <Card key={n.id} className="flex items-start justify-between gap-2">
                <button onClick={() => startEdit(n)} className="text-left">
                  <div className="font-medium">{n.title || 'Untitled'}</div>
                  <div className="line-clamp-2 whitespace-pre-wrap text-xs text-zinc-500">{n.body}</div>
                  <div className="mt-1 text-[10px] text-zinc-600">
                    {new Date(n.updatedAt).toLocaleString()}
                  </div>
                </button>
                <button onClick={() => remove(n.id)} className="text-xs text-red-400 hover:text-red-300">
                  ✕
                </button>
              </Card>
            ))
          )}
        </div>

        <Card>
          <div className="mb-2 flex items-center justify-between">
            <span className="text-sm font-medium">{editing ? 'Edit note' : 'New note'}</span>
            {editing && (
              <Button variant="ghost" onClick={startNew}>
                New
              </Button>
            )}
          </div>
          <input
            value={title}
            onChange={(e) => setTitle(e.target.value)}
            placeholder="Title"
            className="mb-2 w-full rounded-lg border border-zinc-700 bg-zinc-950 px-3 py-1.5 text-sm outline-none focus:border-zinc-500"
          />
          <textarea
            value={body}
            onChange={(e) => setBody(e.target.value)}
            placeholder="Markdown…"
            rows={12}
            className="w-full rounded-lg border border-zinc-700 bg-zinc-950 px-3 py-2 font-mono text-xs outline-none focus:border-zinc-500"
          />
          <div className="mt-2 flex justify-end">
            <Button onClick={save} disabled={!title.trim() && !body.trim()}>
              {editing ? 'Save changes' : 'Create note'}
            </Button>
          </div>
        </Card>
      </div>
    </div>
  )
}
