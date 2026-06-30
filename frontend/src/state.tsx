import { createContext, useCallback, useContext, useEffect, useMemo, useRef, useState, type ReactNode } from 'react'
import { api, type Domain } from './api'

interface AppState {
  domains: Domain[]
  loading: boolean
  selectedId: number | null
  selected: Domain | null
  select: (id: number | null) => void
  refreshDomains: () => Promise<void>
}

const Ctx = createContext<AppState | null>(null)

export function AppProvider({ children }: { children: ReactNode }) {
  const [domains, setDomains] = useState<Domain[]>([])
  const [loading, setLoading] = useState(true)
  const [selectedId, setSelectedId] = useState<number | null>(null)

  const refreshDomains = useCallback(async () => {
    const { domains } = await api.domains()
    setDomains(domains)
    setSelectedId((cur) => {
      if (cur && domains.some((d) => d.id === cur)) return cur
      return domains[0]?.id ?? null
    })
  }, [])

  useEffect(() => {
    refreshDomains().finally(() => setLoading(false))
  }, [refreshDomains])

  const value = useMemo<AppState>(
    () => ({
      domains,
      loading,
      selectedId,
      selected: domains.find((d) => d.id === selectedId) ?? null,
      select: setSelectedId,
      refreshDomains,
    }),
    [domains, loading, selectedId, refreshDomains],
  )

  return <Ctx.Provider value={value}>{children}</Ctx.Provider>
}

export function useApp(): AppState {
  const ctx = useContext(Ctx)
  if (!ctx) throw new Error('useApp must be used within AppProvider')
  return ctx
}

// Host options for a domain (apex + discovered subdomains), live hosts first.
// Used by the Scans/Fuzzing target pickers.
export function useHosts(domain: Domain | null): { host: string; live: boolean }[] {
  const [hosts, setHosts] = useState<{ host: string; live: boolean }[]>([])
  useEffect(() => {
    if (!domain) {
      setHosts([])
      return
    }
    let cancelled = false
    api
      .subdomains(domain.id)
      .then((r) => {
        if (cancelled) return
        const list = r.subdomains.map((s) => ({ host: s.host, live: s.httpStatus != null }))
        if (!list.some((h) => h.host === domain.host)) list.unshift({ host: domain.host, live: false })
        list.sort((a, b) => Number(b.live) - Number(a.live) || a.host.localeCompare(b.host))
        setHosts(list)
      })
      .catch(() => {
        if (!cancelled) setHosts([{ host: domain.host, live: false }])
      })
    return () => {
      cancelled = true
    }
  }, [domain])
  return hosts
}

// Small polling hook for job-driven views. Ref-based so the interval always
// calls the LATEST callback (avoids stale-closure bugs when the callback closes
// over changing state like a job id), without tearing down the interval on
// every render.
export function usePoll(fn: () => void, intervalMs: number, active = true) {
  const fnRef = useRef(fn)
  useEffect(() => {
    fnRef.current = fn
  })
  useEffect(() => {
    if (!active) return
    fnRef.current()
    const t = setInterval(() => fnRef.current(), intervalMs)
    return () => clearInterval(t)
  }, [active, intervalMs])
}
