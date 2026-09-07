import { useCallback, useEffect, useRef, useState } from 'react'
import { Repeat, Crosshair, KeyRound, FlaskConical, Fingerprint, Network } from 'lucide-react'
import { api, type Identity } from '../api'
import { useApp } from '../state'
import { Empty, PageHeader } from '../components/ui'
import { Tabs } from '../components/Tabs'
import { useToast } from '../components/Toast'
import { useConfirm } from '../components/Confirm'
import { takePendingReplay } from '../lib/replayHandoff'
import { type BuiltReq, METHODS, parseHeaders } from './replay/shared'
import { RequestEditor } from './replay/RequestEditor'
import { IdentityBar } from './replay/IdentityBar'
import { SitemapPanel } from './replay/SitemapPanel'
import { RepeaterPanel } from './replay/RepeaterPanel'
import { IntruderPanel } from './replay/IntruderPanel'
import { AuthzPanel } from './replay/AuthzPanel'
import { InjectPanel } from './replay/InjectPanel'
import { JwtPanel } from './replay/JwtPanel'
import { MatchReplacePanel } from './replay/MatchReplacePanel'

export function Replay() {
  const { selected } = useApp()
  const toast = useToast()
  const ask = useConfirm()
  const [mode, setMode] = useState<'repeater' | 'intruder' | 'authz' | 'inject' | 'jwt' | 'sitemap'>('repeater')

  // Shared request editor state.
  const [method, setMethod] = useState<(typeof METHODS)[number]>('GET')
  const [url, setUrl] = useState('')
  const [headersText, setHeadersText] = useState('')
  const [bodyText, setBodyText] = useState('')
  const [followRedirects, setFollowRedirects] = useState(false)

  // Named identities (A / B / anon) reusable across Repeater / Intruder / authz.
  const [identities, setIdentities] = useState<Identity[]>([])
  const [identityId, setIdentityId] = useState<number | null>(null)
  const reloadIdentities = useCallback(() => {
    if (!selected) return
    api
      .identities(selected.id)
      .then((r) => setIdentities(r.identities))
      .catch(() => setIdentities([]))
  }, [selected])
  useEffect(() => {
    setIdentityId(null)
    reloadIdentities()
  }, [reloadIdentities])

  // Load a request (from the Traffic handoff or a history entry) into the editor.
  const applyRequest = useCallback((r: BuiltReq) => {
    if ((METHODS as readonly string[]).includes(r.method)) setMethod(r.method as (typeof METHODS)[number])
    setUrl(r.url)
    setHeadersText(r.headers.map(([k, v]) => `${k}: ${v}`).join('\n'))
    setBodyText(typeof r.body === 'string' ? r.body : '')
  }, [])

  // Prefill the URL from the selected target the first time (and when switching to
  // a target while the box is still empty/pointing at the old host).
  const lastHost = useRef<string | null>(null)
  useEffect(() => {
    if (!selected) return
    const prevDefault = `https://${lastHost.current}/`
    // Functional update reads the CURRENT url, not a stale closure — so it won't
    // clobber a URL just set by the "Send to Replay" handoff (and stays correct
    // under React StrictMode's double-invoked effects).
    setUrl((cur) => (!cur || cur === prevDefault ? `https://${selected.host}/` : cur))
    lastHost.current = selected.host
  }, [selected])

  // Consume a request handed over from Traffic / Findings / the attack graph.
  useEffect(() => {
    const p = takePendingReplay()
    if (!p) return
    setMode(p.mode === 'intruder' ? 'intruder' : 'repeater')
    applyRequest({ method: p.method, url: p.url, headers: p.headers, body: p.body })
  }, [applyRequest])

  if (!selected) return <Empty>Select a domain to compose and replay requests against it.</Empty>

  const passive = selected.mode !== 'active_authorized'

  async function confirmActive(title: string, what: string): Promise<boolean> {
    if (!passive) return true
    return ask({
      title,
      message: `${selected!.host} is passive_only.\n\n${what} sends real traffic to the target. Only continue if you are authorized to actively test it.`,
      confirmLabel: 'Send anyway',
      tone: 'danger',
    })
  }

  return (
    <div className="flex min-h-[calc(100dvh-7rem)] flex-col">
      <PageHeader
        title="Replay"
        subtitle={`${selected.host} — compose, send and fuzz requests (server-side, scoped to this target)`}
        actions={
          <Tabs
            label="Replay tool"
            value={mode}
            onChange={setMode}
            items={[
              { key: 'repeater', label: 'Repeater', icon: <Repeat size={14} /> },
              { key: 'intruder', label: 'Intruder', icon: <Crosshair size={14} /> },
              { key: 'authz', label: 'Authz', icon: <KeyRound size={14} /> },
              { key: 'inject', label: 'Inject', icon: <FlaskConical size={14} /> },
              { key: 'jwt', label: 'JWT', icon: <Fingerprint size={14} /> },
              { key: 'sitemap', label: 'Sitemap', icon: <Network size={14} /> },
            ]}
          />
        }
      />

      {mode !== 'sitemap' && <MatchReplacePanel domainId={selected.id} domainHost={selected.host} toast={toast} />}

      {(mode === 'repeater' || mode === 'intruder' || mode === 'authz') && (
        <IdentityBar
          domainId={selected.id}
          identities={identities}
          identityId={identityId}
          setIdentityId={setIdentityId}
          onChange={reloadIdentities}
          selectable={mode !== 'authz'}
          toast={toast}
        />
      )}

      {mode === 'sitemap' ? (
        <div role="tabpanel" aria-label="Sitemap tool">
          <SitemapPanel
            domainId={selected.id}
            onOpen={(m, u) => {
              if ((METHODS as readonly string[]).includes(m)) setMethod(m as (typeof METHODS)[number])
              setUrl(u)
              setMode('repeater')
            }}
          />
        </div>
      ) : (
      <div role="tabpanel" aria-label={`${mode} tool`} className="grid min-h-0 flex-1 gap-4 lg:grid-cols-2 lg:grid-rows-1">
        <RequestEditor
          mode={mode}
          method={method}
          setMethod={setMethod}
          url={url}
          setUrl={setUrl}
          headersText={headersText}
          setHeadersText={setHeadersText}
          bodyText={bodyText}
          setBodyText={setBodyText}
          followRedirects={followRedirects}
          setFollowRedirects={setFollowRedirects}
        />
        {mode === 'repeater' && (
          <RepeaterPanel
            domainId={selected.id}
            passive={passive}
            confirmActive={confirmActive}
            applyRequest={applyRequest}
            reqStr={`${method} ${url}\n${headersText}\n\n${bodyText}`.trimEnd()}
            build={() => ({
              method,
              url,
              headers: parseHeaders(headersText),
              body: method === 'GET' || method === 'HEAD' ? undefined : bodyText || undefined,
              followRedirects,
            })}
            identityId={identityId}
            toast={toast}
          />
        )}
        {mode === 'intruder' && (
          <IntruderPanel
            domainId={selected.id}
            passive={passive}
            confirmActive={confirmActive}
            build={() => ({
              method,
              url,
              headers: parseHeaders(headersText),
              body: method === 'GET' || method === 'HEAD' ? undefined : bodyText || undefined,
              followRedirects,
            })}
            identityId={identityId}
            toast={toast}
          />
        )}
        {mode === 'authz' && (
          <AuthzPanel
            domainId={selected.id}
            passive={passive}
            confirmActive={confirmActive}
            build={() => ({
              method,
              url,
              headers: parseHeaders(headersText),
              body: method === 'GET' || method === 'HEAD' ? undefined : bodyText || undefined,
              followRedirects,
            })}
            identities={identities}
            toast={toast}
          />
        )}
        {mode === 'inject' && (
          <InjectPanel
            domainId={selected.id}
            passive={passive}
            confirmActive={confirmActive}
            build={() => ({
              method,
              url,
              headers: parseHeaders(headersText),
              body: method === 'GET' || method === 'HEAD' ? undefined : bodyText || undefined,
              followRedirects,
            })}
            toast={toast}
          />
        )}
        {mode === 'jwt' && (
          <JwtPanel
            domainId={selected.id}
            passive={passive}
            confirmActive={confirmActive}
            build={() => ({
              method,
              url,
              headers: parseHeaders(headersText),
              body: method === 'GET' || method === 'HEAD' ? undefined : bodyText || undefined,
              followRedirects,
            })}
            toast={toast}
          />
        )}
      </div>
      )}
    </div>
  )
}


