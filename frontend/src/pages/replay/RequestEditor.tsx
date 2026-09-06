import { Card } from '../../components/ui'
import { METHODS, PAYLOAD_MARKER } from './shared'

export function RequestEditor(props: {
  mode: 'repeater' | 'intruder' | 'authz' | 'inject' | 'jwt'
  method: (typeof METHODS)[number]
  setMethod: (m: (typeof METHODS)[number]) => void
  url: string
  setUrl: (s: string) => void
  headersText: string
  setHeadersText: (s: string) => void
  bodyText: string
  setBodyText: (s: string) => void
  followRedirects: boolean
  setFollowRedirects: (b: boolean) => void
}) {
  const bodyless = props.method === 'GET' || props.method === 'HEAD'
  return (
    <Card className="flex h-full min-h-0 flex-col">
      <div className="mb-2 flex items-center gap-2">
        <select
          value={props.method}
          onChange={(e) => props.setMethod(e.target.value as (typeof METHODS)[number])}
          className="rounded-lg border border-hair bg-ink-950 px-2 py-2 font-mono text-xs outline-none focus:border-accent-500"
        >
          {METHODS.map((m) => (
            <option key={m} value={m}>
              {m}
            </option>
          ))}
        </select>
        <input
          value={props.url}
          onChange={(e) => props.setUrl(e.target.value)}
          placeholder="https://host/path"
          spellCheck={false}
          className="min-w-0 flex-1 rounded-lg border border-hair bg-ink-950 px-3 py-2 font-mono text-xs outline-none focus:border-accent-500"
        />
      </div>
      {props.mode === 'intruder' && (
        <p className="mb-2 text-xs text-zinc-500">
          Mark payload positions with <code className="rounded bg-ink-800 px-1 font-mono text-accent-fg">{'{{P1}}'}</code>,{' '}
          <code className="rounded bg-ink-800 px-1 font-mono text-accent-fg">{'{{P2}}'}</code>, … (or{' '}
          <code className="rounded bg-ink-800 px-1 font-mono text-accent-fg">{PAYLOAD_MARKER}</code> = P1) — in the URL, a
          header value, or the body.
        </p>
      )}
      {props.mode === 'authz' && (
        <p className="mb-2 text-xs text-zinc-500">
          Compose an <span className="text-zinc-300">authenticated</span> request for one of YOUR objects, marking the object id
          with <code className="rounded bg-ink-800 px-1 font-mono text-accent-fg">{'{{ID}}'}</code>. It’s replayed under your creds,
          a second identity, and anonymously to spot broken access control.
        </p>
      )}
      {props.mode === 'inject' && (
        <p className="mb-2 text-xs text-zinc-500">
          Mark the injection point with <code className="rounded bg-ink-800 px-1 font-mono text-accent-fg">{'{{INJ}}'}</code>. The
          differential payloads below are substituted there to PROVE a blind SQLi (boolean and/or time-based).
        </p>
      )}
      {props.mode === 'jwt' && (
        <p className="mb-2 text-xs text-zinc-500">
          Mark the token slot with <code className="rounded bg-ink-800 px-1 font-mono text-accent-fg">{'{{JWT}}'}</code> (e.g.{' '}
          <code className="rounded bg-ink-800 px-1 font-mono text-accent-fg">Authorization: Bearer {'{{JWT}}'}</code>). The original
          RS256 token goes below; the job forges an HS256 token with the server’s public key to prove alg confusion.
        </p>
      )}
      <label className="mb-1 block text-[10px] uppercase tracking-wide text-zinc-600">Headers (one per line: Name: Value)</label>
      <textarea
        value={props.headersText}
        onChange={(e) => props.setHeadersText(e.target.value)}
        placeholder={'Cookie: session=…\nAuthorization: Bearer …\nContent-Type: application/json'}
        rows={5}
        spellCheck={false}
        className="mb-2 block min-h-0 w-full flex-1 resize-none rounded-lg border border-hair bg-ink-950 px-3 py-2 font-mono text-xs outline-none focus:border-accent-500"
      />
      <label className="mb-1 block text-[10px] uppercase tracking-wide text-zinc-600">
        Body {bodyless && <span className="text-zinc-600">(ignored for {props.method})</span>}
      </label>
      <textarea
        value={props.bodyText}
        onChange={(e) => props.setBodyText(e.target.value)}
        placeholder={bodyless ? '' : '{"code":"' + PAYLOAD_MARKER + '"}'}
        rows={6}
        spellCheck={false}
        disabled={bodyless}
        className="block min-h-0 w-full flex-1 resize-none rounded-lg border border-hair bg-ink-950 px-3 py-2 font-mono text-xs outline-none focus:border-accent-500 disabled:opacity-50"
      />
    </Card>
  )
}
