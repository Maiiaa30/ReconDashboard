import { useCallback, useEffect, useState } from 'react'
import { api, ApiError } from '../api'
import type { OwaspCategory, OwaspProfileKey, DomainProfile, Finding } from '../api'
import { useApp, usePoll } from '../state'
import { Badge, Button, Card, Empty, PageHeader, ScoreBadge } from '../components/ui'
import { timeAgo } from '../lib/format'

// Map a nuclei severity string to a Badge tone, so high/critical reads red.
function severityTone(severity: unknown): 'zinc' | 'green' | 'amber' | 'red' | 'blue' {
  switch (String(severity ?? '').toLowerCase()) {
    case 'critical':
    case 'high':
      return 'red'
    case 'medium':
      return 'amber'
    case 'low':
      return 'blue'
    case 'info':
      return 'green'
    default:
      return 'zinc'
  }
}

// A category applies if it has no requirements, or any required profile flag is on.
function isApplicable(category: OwaspCategory, profile: DomainProfile): boolean {
  if (category.requires.length === 0) return true
  return category.requires.some((k) => profile[k as keyof DomainProfile] === true)
}

function CategoryCard({
  category,
  applicable,
  canRun,
  busy,
  onRun,
}: {
  category: OwaspCategory
  applicable: boolean
  canRun: boolean
  busy: string | null
  onRun: (category: OwaspCategory) => void
}) {
  const [showPayloads, setShowPayloads] = useState(false)
  const running = busy === category.id

  return (
    <Card>
      <div className="mb-2 flex items-start justify-between gap-2">
        <h3 className="text-sm font-semibold text-zinc-100">{category.name}</h3>
        {category.requires.length === 0 ? (
          <Badge tone="green">always</Badge>
        ) : applicable ? (
          <Badge tone="green">applicable</Badge>
        ) : (
          <Badge tone="zinc">n/a — needs: {category.requires.join(', ')}</Badge>
        )}
      </div>

      <p className="text-sm text-zinc-400">{category.description}</p>

      {category.tags.length > 0 && (
        <div className="mt-2 flex flex-wrap gap-1">
          {category.tags.map((t) => (
            <Badge key={t} tone="zinc">
              {t}
            </Badge>
          ))}
        </div>
      )}

      <div className="mt-3 flex items-center gap-2">
        <Button
          variant="loud"
          className="px-2.5 py-1 text-xs"
          disabled={!canRun || !applicable || busy != null}
          onClick={() => onRun(category)}
        >
          {running ? 'Queuing…' : 'Run'}
        </Button>
        <button
          type="button"
          onClick={() => setShowPayloads((v) => !v)}
          className="text-xs text-zinc-500 transition hover:text-zinc-300"
        >
          payloads {showPayloads ? '▾' : '▸'}
        </button>
      </div>

      {showPayloads && (
        <div className="mt-3 space-y-1 rounded-lg border border-zinc-800 bg-zinc-950/60 p-2">
          {category.payloads.length === 0 ? (
            <p className="text-xs text-zinc-500">No reference payloads.</p>
          ) : (
            category.payloads.map((p, i) => (
              <code key={i} className="block break-all font-mono text-xs text-zinc-300">
                {p}
              </code>
            ))
          )}
        </div>
      )}
    </Card>
  )
}

export function Owasp() {
  const { selected, refreshDomains } = useApp()

  const [catalog, setCatalog] = useState<OwaspCategory[]>([])
  const [profileKeys, setProfileKeys] = useState<OwaspProfileKey[]>([])
  const [nucleiInstalled, setNucleiInstalled] = useState<boolean | null>(null)
  const [findings, setFindings] = useState<Finding[]>([])

  // Optimistic local copy of the profile, re-seeded when the selected domain changes.
  const [profile, setProfile] = useState<DomainProfile>(selected?.profile ?? {})

  // A single busy token: a category id, or 'all', or 'profile'. null = idle.
  const [busy, setBusy] = useState<string | null>(null)
  const [runMessage, setRunMessage] = useState<string | null>(null)
  const [runError, setRunError] = useState<string | null>(null)

  const selectedId = selected?.id ?? null

  // Re-seed the local profile when the selected domain changes.
  useEffect(() => {
    setProfile(selected?.profile ?? {})
    setRunMessage(null)
    setRunError(null)
  }, [selectedId]) // eslint-disable-line react-hooks/exhaustive-deps

  // Fetch the catalog + meta once.
  useEffect(() => {
    api
      .owaspCatalog()
      .then((r) => {
        setCatalog(r.catalog)
        setProfileKeys(r.profileKeys)
      })
      .catch(() => {})
    api
      .meta()
      .then((m) => setNucleiInstalled(m.tools.nuclei))
      .catch(() => setNucleiInstalled(false))
  }, [])

  // Poll nuclei findings for the selected domain every 6s.
  const loadFindings = useCallback(() => {
    if (selectedId == null) return
    api
      .findings({ domainId: selectedId, type: 'nuclei', limit: 500 })
      .then((r) => setFindings(r.findings))
      .catch(() => {})
  }, [selectedId])
  usePoll(loadFindings, 6000, selectedId != null)

  if (!selected) return <Empty>Select a domain to run OWASP tests.</Empty>

  const active = selected.mode === 'active_authorized'
  const nucleiOk = nucleiInstalled === true
  const canRun = active && nucleiOk
  const applicableCount = catalog.filter((c) => isApplicable(c, profile)).length

  async function toggleProfile(key: keyof DomainProfile, checked: boolean): Promise<void> {
    if (!selected) return
    const next: DomainProfile = { ...profile, [key]: checked }
    setProfile(next) // optimistic
    setBusy(`profile:${key}`)
    setRunError(null)
    try {
      await api.updateDomain(selected.id, { profile: next })
      await refreshDomains()
    } catch (err) {
      setProfile(profile) // revert
      setRunError(err instanceof ApiError ? err.message : 'failed to save app profile')
    } finally {
      setBusy(null)
    }
  }

  async function runAllApplicable(): Promise<void> {
    if (!selected) return
    setBusy('all')
    setRunMessage(null)
    setRunError(null)
    try {
      const { jobId, categories } = await api.runOwasp(selected.id)
      setRunMessage(
        `Queued job #${jobId} covering ${categories.length ? categories.join(', ') : '(none)'}`,
      )
    } catch (err) {
      setRunError(err instanceof ApiError ? err.message : 'failed to queue OWASP tests')
    } finally {
      setBusy(null)
    }
  }

  async function runCategory(category: OwaspCategory): Promise<void> {
    if (!selected) return
    setBusy(category.id)
    setRunMessage(null)
    setRunError(null)
    try {
      const { jobId, categories } = await api.runOwasp(selected.id, [category.id])
      setRunMessage(
        `Queued job #${jobId} covering ${categories.length ? categories.join(', ') : category.id}`,
      )
    } catch (err) {
      setRunError(err instanceof ApiError ? err.message : 'failed to queue OWASP test')
    } finally {
      setBusy(null)
    }
  }

  return (
    <div>
      <PageHeader
        title="OWASP Top 10"
        subtitle={`${selected.host} — nuclei-driven, profile-filtered`}
        actions={<Badge tone="amber">LOUD / ACTIVE</Badge>}
      />

      {!active && (
        <Card className="mb-6 border-amber-900/60 bg-amber-950/30">
          <div className="mb-1 flex items-center gap-2">
            <Badge tone="amber">disabled</Badge>
            <span className="text-sm font-medium text-amber-200">
              OWASP tests are disabled for passive_only domains
            </span>
          </div>
          <p className="text-sm text-amber-200/80">
            These are loud, active nuclei scans. The operator must mark{' '}
            <span className="font-mono">{selected.host}</span> as{' '}
            <span className="font-mono">active_authorized</span> (in the Domains tab) — and only for a
            target you are authorized to actively test — before running these.
          </p>
        </Card>
      )}

      {nucleiInstalled === false && (
        <Card className="mb-6 border-amber-900/60 bg-amber-950/30">
          <div className="flex items-center gap-2">
            <Badge tone="amber">unavailable</Badge>
            <span className="text-sm text-amber-200">
              nuclei is not installed in this image — tests cannot run.
            </span>
          </div>
        </Card>
      )}

      {/* App profile / filter */}
      <Card className="mb-6">
        <h2 className="text-sm font-semibold text-zinc-200">App profile</h2>
        <p className="mt-1 text-sm text-zinc-500">
          Tests only run for categories that match your app. e.g. access-control tests need a login.
        </p>
        <div className="mt-3 grid gap-2 sm:grid-cols-2">
          {profileKeys.map((pk) => {
            const checked = profile[pk.key] === true
            return (
              <label
                key={String(pk.key)}
                className="flex items-start gap-2 rounded-lg border border-zinc-800 bg-zinc-950/40 p-2.5"
              >
                <input
                  type="checkbox"
                  checked={checked}
                  disabled={busy != null}
                  onChange={(e) => toggleProfile(pk.key, e.target.checked)}
                  className="mt-0.5 h-4 w-4 accent-amber-500"
                />
                <span className="text-sm">
                  <span className="font-medium text-zinc-200">{pk.label}</span>
                  <span className="block text-xs text-zinc-500">{pk.hint}</span>
                </span>
              </label>
            )
          })}
        </div>
      </Card>

      {/* Run all */}
      <div className="mb-4 flex flex-wrap items-center gap-3">
        <Button variant="loud" disabled={!canRun || busy != null} onClick={runAllApplicable}>
          {busy === 'all' ? 'Queuing…' : 'Run all applicable'}
        </Button>
        <span className="text-sm text-zinc-500">
          {applicableCount} of {catalog.length} categories applicable
        </span>
      </div>

      {runMessage && <p className="mb-3 text-sm text-green-400">{runMessage}</p>}
      {runError && <p className="mb-3 text-sm text-red-400">{runError}</p>}

      {/* Category cards */}
      {catalog.length === 0 ? (
        <Empty>Loading OWASP catalog…</Empty>
      ) : (
        <div className="grid gap-4 sm:grid-cols-2">
          {catalog.map((c) => (
            <CategoryCard
              key={c.id}
              category={c}
              applicable={isApplicable(c, profile)}
              canRun={canRun}
              busy={busy}
              onRun={runCategory}
            />
          ))}
        </div>
      )}

      {/* Results */}
      <h2 className="mb-3 mt-8 text-sm font-semibold text-zinc-200">Results</h2>
      {findings.length === 0 ? (
        <Empty>No OWASP findings yet. Configure the profile and run tests.</Empty>
      ) : (
        <div className="space-y-2">
          {findings.map((f) => {
            const data = f.data ?? {}
            return (
              <Card key={f.id}>
                <div className="flex flex-wrap items-center gap-2">
                  <ScoreBadge score={f.score} />
                  <Badge tone={severityTone(data.severity)}>{String(data.severity ?? 'info')}</Badge>
                  <span className="text-sm font-medium text-zinc-100">
                    {data.name || data.templateId || 'finding'}
                  </span>
                  {data.owaspCategory && <Badge tone="blue">{String(data.owaspCategory)}</Badge>}
                  <span className="ml-auto text-xs text-zinc-500">
                    {timeAgo(new Date(f.createdAt).getTime())}
                  </span>
                </div>
                {data.matched && (
                  <code className="mt-2 block break-all font-mono text-xs text-zinc-400">
                    {String(data.matched)}
                  </code>
                )}
              </Card>
            )
          })}
        </div>
      )}
    </div>
  )
}
