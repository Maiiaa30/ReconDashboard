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
