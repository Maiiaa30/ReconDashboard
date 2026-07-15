import { useEffect, useMemo, useState } from 'react'
import {
  Home as HomeIcon, Globe, Brain, Network, Camera, Crosshair, Radar, Eye, ShieldAlert, FileText,
  Activity, ScanSearch, ShieldCheck, Flag, StickyNote, PenTool, ScrollText,
  Settings as SettingsIcon, LogOut, Menu, X, Search, Radar as RadarLogo, Wrench, History, ListChecks, Bot, Fingerprint, DatabaseZap, Router, ChevronsLeft, ChevronsRight, Webhook, Repeat, Radio, type LucideIcon,
} from 'lucide-react'
import { CommandPalette } from './CommandPalette'
import { ErrorBoundary } from './ErrorBoundary'
import { JobNotifier } from './JobNotifier'
import type { Me, Job } from '../api'
import { api } from '../api'
import { useApp, usePoll } from '../state'
import { Domains } from '../pages/Domains'
import { Intel } from '../pages/Intel'
import { Methodology } from '../pages/Methodology'
import { Subdomains } from '../pages/Subdomains'
import { Screenshots } from '../pages/Screenshots'
import { Fuzzing } from '../pages/Fuzzing'
import { Exposure } from '../pages/Exposure'
import { Ports } from '../pages/Ports'
import { Osint } from '../pages/Osint'
import { SocialForensics } from '../pages/SocialForensics'
import { DataLeaks } from '../pages/DataLeaks'
import { Origin } from '../pages/Origin'
import { ApiSurface } from '../pages/ApiSurface'
import { Replay } from '../pages/Replay'
import { Traffic } from '../pages/Traffic'
import { Whois } from '../pages/Whois'
import { CheckHost } from '../pages/CheckHost'
import { Scans } from '../pages/Scans'
import { Tools } from '../pages/Tools'
import { Owasp } from '../pages/Owasp'
import { LlmSecurity } from '../pages/LlmSecurity'
import { Notes } from '../pages/Notes'
import { Canvas } from '../pages/Canvas'
import { Findings } from '../pages/Findings'
import { Jobs } from '../pages/Jobs'
import { Audit } from '../pages/Audit'
import { Home } from '../pages/Home'
import { Settings } from '../pages/Settings'

// Nav grouped into labeled sections so a 20+ item list stays scannable instead
// of being one long undifferentiated column.
const NAV_SECTIONS: { title: string; items: { key: string; label: string; icon: LucideIcon }[] }[] = [
  {
    title: 'Overview',
    items: [
      { key: 'home', label: 'Home', icon: HomeIcon },
      { key: 'domains', label: 'Domains', icon: Globe },
      { key: 'intel', label: 'Intel', icon: Brain },
      { key: 'methodology', label: 'Methodology', icon: ListChecks },
    ],
  },
  {
    title: 'Recon',
    items: [
      { key: 'subdomains', label: 'Subdomains', icon: Network },
      { key: 'screenshots', label: 'Screenshots', icon: Camera },
      { key: 'exposure', label: 'Exposure', icon: Radar },
      { key: 'ports', label: 'Ports', icon: Router },
      { key: 'api', label: 'API Surface', icon: Webhook },
      { key: 'osint', label: 'OSINT', icon: Eye },
    ],
  },
  {
    title: 'OSINT & Leaks',
    items: [
      { key: 'social', label: 'Social Forensics', icon: Fingerprint },
      { key: 'leaks', label: 'Data Leaks', icon: DatabaseZap },
      { key: 'whois', label: 'WHOIS', icon: FileText },
      { key: 'checkhost', label: 'Check Host', icon: Activity },
    ],
  },
  {
    title: 'Offensive',
    items: [
      { key: 'scans', label: 'Scans', icon: ScanSearch },
      { key: 'fuzzing', label: 'Fuzzing', icon: Crosshair },
      { key: 'tools', label: 'Tools', icon: Wrench },
      { key: 'owasp', label: 'OWASP', icon: ShieldCheck },
      { key: 'origin', label: 'WAF / Origin', icon: ShieldAlert },
      { key: 'llm', label: 'LLM Security', icon: Bot },
    ],
  },
  {
    title: 'Capture & Replay',
    items: [
      { key: 'traffic', label: 'Traffic', icon: Radio },
      { key: 'replay', label: 'Replay', icon: Repeat },
    ],
  },
  {
    title: 'Workspace',
    items: [
      { key: 'findings', label: 'Findings', icon: Flag },
      { key: 'notes', label: 'Notes', icon: StickyNote },
      { key: 'canvas', label: 'Canvas', icon: PenTool },
    ],
  },
  {
    title: 'System',
    items: [
      { key: 'jobs', label: 'Logs', icon: ScrollText },
      { key: 'audit', label: 'Audit', icon: History },
      { key: 'settings', label: 'Settings', icon: SettingsIcon },
    ],
  },
]

const MODULES = NAV_SECTIONS.flatMap((s) => s.items)

// Flat index (with section) for the command palette's fuzzy search.
const MODULE_INDEX = NAV_SECTIONS.flatMap((s) => s.items.map((it) => ({ key: it.key, label: it.label, section: s.title })))

type ModuleKey = (typeof MODULES)[number]['key']

// Modules that operate on a selected domain show the domain picker.
const DOMAIN_SCOPED: ModuleKey[] = ['intel', 'methodology', 'subdomains', 'screenshots', 'fuzzing', 'replay', 'traffic', 'exposure', 'ports', 'api', 'osint', 'leaks', 'origin', 'scans', 'tools', 'owasp', 'notes']

// Map a job type to the nav module whose page shows its results, so a running /
// just-finished job can flag that item in the sidebar.
const JOB_MODULE: Record<string, ModuleKey> = {
  subdomain_discovery: 'subdomains',
  screenshot: 'screenshots',
  exposure_scan: 'exposure',
  osint_gather: 'osint',
  origin_scan: 'origin',
  leak_check: 'leaks',
  api_discovery: 'api',
  nmap_scan: 'scans',
  nuclei_scan: 'scans',
  ffuf_scan: 'fuzzing',
  owasp_active: 'owasp',
  tool_scan: 'tools',
  intruder: 'replay',
}
const PENDING = new Set(['queued', 'running'])

export function Shell({ me, onLogout }: { me: Me; onLogout: () => void }) {
  const { domains, selectedId, selected, select } = useApp()
  // Persist the current page so a refresh stays put instead of jumping to Home.
  const [active, setActive] = useState<ModuleKey>(() => {
    try {
      const saved = localStorage.getItem('activePage')
      if (saved && MODULES.some((m) => m.key === saved)) return saved as ModuleKey
    } catch {
      /* storage unavailable */
    }
    return 'home'
  })
  useEffect(() => {
    try {
      localStorage.setItem('activePage', active)
    } catch {
      /* storage unavailable — page just won't persist */
    }
  }, [active])
  const [navOpen, setNavOpen] = useState(false)
  const [paletteOpen, setPaletteOpen] = useState(false)
  // Desktop-only: collapse the sidebar to an icon rail. Persisted so it sticks
  // across reloads. Ignored on mobile, where the drawer always shows full width.
  const [collapsed, setCollapsed] = useState(() => {
    try {
      return localStorage.getItem('sidebarCollapsed') === '1'
    } catch {
      return false
    }
  })
  useEffect(() => {
    try {
      localStorage.setItem('sidebarCollapsed', collapsed ? '1' : '0')
    } catch {
      /* storage unavailable — collapse just won't persist */
    }
  }, [collapsed])
  const activeLabel = MODULES.find((m) => m.key === active)?.label ?? 'Recon Dashboard'

  // Sidebar job status dots: yellow while a module's job runs, green once it
  // finishes — cleared when the operator opens that page.
  const [jobs, setJobs] = useState<Job[]>([])
  const [seen, setSeen] = useState<Record<string, number>>({})
  usePoll(
    () => {
      api
        .jobs()
        .then((r) => setJobs(r.jobs))
        .catch(() => {})
      // Treat the page you're on as continuously seen, so a job that finishes
      // while you're watching it doesn't later light up green.
      setSeen((s) => ({ ...s, [active]: Date.now() }))
    },
    3500,
    true,
    active,
  )

  const navStatus = useMemo(() => {
    const out: Partial<Record<ModuleKey, 'running' | 'ready'>> = {}
    for (const j of jobs) {
      const key = JOB_MODULE[j.type]
      if (!key) continue
      if (j.domainId != null && selectedId != null && j.domainId !== selectedId) continue // other target
      if (PENDING.has(j.status)) {
        out[key] = 'running'
      } else if (j.status === 'done' && key !== active && out[key] !== 'running') {
        const fin = j.finishedAt ? new Date(j.finishedAt).getTime() : 0
        if (fin > (seen[key] ?? 0)) out[key] = 'ready'
      }
    }
    return out
  }, [jobs, seen, selectedId, active])

  // Global ⌘/Ctrl-K toggles the command palette.
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && (e.key === 'k' || e.key === 'K')) {
        e.preventDefault()
        setPaletteOpen((v) => !v)
      }
    }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [])

  // Deep-link from cross-target views (Home): switch page and optionally target.
  const navigate = (page: string, domainId?: number) => {
    if (domainId != null) select(domainId)
    setActive(page)
    setNavOpen(false)
  }

  async function logout() {
    try {
      await api.logout()
    } finally {
      // Always drop the local session view, even if the request fails.
      onLogout()
    }
  }

  return (
    <div className="min-h-full bg-ink-950 text-zinc-100 md:flex">
      <JobNotifier />
      {/* Mobile top bar — shows the current page and toggles the drawer. */}
      <header className="md:hidden sticky top-0 z-20 flex items-center gap-3 border-b border-hair bg-ink-950/95 px-4 py-3 backdrop-blur">
        <button
          onClick={() => setNavOpen((v) => !v)}
          aria-label={navOpen ? 'Close menu' : 'Open menu'}
          className="text-zinc-300 transition hover:text-zinc-100"
        >
          {navOpen ? <X size={20} /> : <Menu size={20} />}
        </button>
        <span className="flex h-6 w-6 items-center justify-center rounded bg-accent-500 shadow-sm shadow-accent-500/30">
          <RadarLogo size={14} className="text-white" />
        </span>
        <span className="truncate text-sm font-semibold">{activeLabel}</span>
      </header>

      {/* Dim backdrop behind the mobile drawer (tap to close). */}
      {navOpen && (
        <div className="fixed inset-0 z-30 bg-black/60 backdrop-blur-sm md:hidden" onClick={() => setNavOpen(false)} />
      )}

      {/* Sidebar: a static column on desktop, a slide-in drawer on mobile. */}
      <aside
        className={`fixed inset-y-0 left-0 z-40 flex w-64 flex-col border-r border-hair bg-ink-900 transition-[transform,width] duration-200 ease-out md:sticky md:top-0 md:z-auto md:h-screen md:translate-x-0 ${
          collapsed ? 'md:w-16' : 'md:w-56'
        } ${navOpen ? 'translate-x-0' : '-translate-x-full'}`}
      >
        <div className={`flex items-center gap-2.5 px-4 py-4 ${collapsed ? 'md:flex-col md:gap-3 md:px-0' : ''}`}>
          <span className="flex h-8 w-8 shrink-0 items-center justify-center rounded-lg bg-accent-500 shadow-sm shadow-accent-500/30">
            <RadarLogo size={18} className="text-white" />
          </span>
          <div className={`min-w-0 flex-1 ${collapsed ? 'md:hidden' : ''}`}>
            <div className="truncate text-sm font-semibold tracking-tight">Recon Dashboard</div>
            {selected ? (
              <div
                className="flex items-center gap-1 truncate text-xs text-zinc-400"
                title={`Target: ${selected.host} · signed in as ${me.user.username}`}
              >
                <Globe size={11} className="shrink-0 text-accent-400" />
                <span className="truncate font-mono">{selected.host}</span>
              </div>
            ) : (
              <div className="truncate text-xs text-zinc-500" title={`Signed in as ${me.user.username}`}>
                {me.user.username}
              </div>
            )}
          </div>
          {/* Desktop collapse/expand toggle — lives at the top of the sidebar. */}
          <button
            onClick={() => setCollapsed((v) => !v)}
            title={collapsed ? 'Expand sidebar' : 'Collapse sidebar'}
            aria-label={collapsed ? 'Expand sidebar' : 'Collapse sidebar'}
            className="hidden shrink-0 rounded-lg p-1.5 text-zinc-500 transition hover:bg-ink-800 hover:text-zinc-200 md:block"
          >
            {collapsed ? <ChevronsRight size={18} /> : <ChevronsLeft size={18} />}
          </button>
          {/* Mobile drawer close. */}
          <button
            onClick={() => setNavOpen(false)}
            aria-label="Close menu"
            className="shrink-0 text-zinc-500 transition hover:text-zinc-200 md:hidden"
          >
            <X size={18} />
          </button>
        </div>
        <button
          onClick={() => {
            setPaletteOpen(true)
            setNavOpen(false)
          }}
          title="Search (⌘K)"
          className={`mx-2 mb-1 flex items-center gap-2 rounded-lg border border-hair bg-ink-850 px-3 py-2 text-sm text-zinc-500 transition hover:border-hair-strong hover:text-zinc-300 ${collapsed ? 'md:justify-center md:px-0' : ''}`}
        >
          <Search size={15} className="shrink-0" />
          <span className={`flex-1 text-left ${collapsed ? 'md:hidden' : ''}`}>Search…</span>
          <kbd className={`rounded bg-ink-800 px-1.5 py-0.5 text-[10px] ${collapsed ? 'md:hidden' : ''}`}>⌘K</kbd>
        </button>
        <nav className="flex-1 overflow-y-auto px-2 pb-2">
          {NAV_SECTIONS.map((section) => (
            <div key={section.title} className={collapsed ? 'md:border-t md:border-hair/40 md:pt-1 md:first:border-t-0' : ''}>
              <div className={`px-3 pb-1 pt-3 text-[11px] font-semibold uppercase tracking-wider text-zinc-500 ${collapsed ? 'md:hidden' : ''}`}>
                {section.title}
              </div>
              {section.items.map((m) => {
                const Icon = m.icon
                const isActive = active === m.key
                const status = navStatus[m.key]
                return (
                  <button
                    key={m.key}
                    onClick={() => {
                      setActive(m.key)
                      setNavOpen(false)
                    }}
                    title={status ? `${m.label} — ${status === 'running' ? 'running…' : 'new results'}` : m.label}
                    className={`relative flex w-full items-center gap-2.5 rounded-lg px-3 py-2 text-left text-sm transition ${
                      collapsed ? 'md:justify-center md:px-0' : ''
                    } ${
                      isActive
                        ? 'bg-accent-500/15 font-medium text-accent-fg'
                        : 'text-zinc-400 hover:bg-ink-800 hover:text-zinc-200'
                    }`}
                  >
                    <Icon size={17} className={`shrink-0 ${isActive ? 'text-accent-400' : 'text-zinc-500'}`} />
                    <span className={collapsed ? 'md:hidden' : ''}>{m.label}</span>
                    {status && (
                      <span
                        aria-hidden
                        className={`h-2 w-2 shrink-0 rounded-full ${
                          status === 'running' ? 'animate-pulse bg-amber-400' : 'bg-emerald-400'
                        } ${collapsed ? 'md:absolute md:right-1 md:top-1 ml-auto' : 'ml-auto'}`}
                      />
                    )}
                  </button>
                )
              })}
            </div>
          ))}
          {/* Log out lives at the end of the scrolling nav — no fixed bottom bar. */}
          <div className="mt-1 border-t border-hair/40 pt-1">
            <button
              onClick={logout}
              title="Log out"
              className={`flex w-full items-center gap-2.5 rounded-lg px-3 py-2 text-left text-sm text-zinc-400 transition hover:bg-ink-800 hover:text-zinc-200 ${
                collapsed ? 'md:justify-center md:px-0' : ''
              }`}
            >
              <LogOut size={17} className="shrink-0 text-zinc-500" />
              <span className={collapsed ? 'md:hidden' : ''}>Log out</span>
            </button>
          </div>
        </nav>
      </aside>

      <main className="min-w-0 flex-1">
        {/* Desktop top bar — anchors the layout: current page on the left, the
            single global target switcher on the right (no more loose floating row). */}
        <div className="sticky top-0 z-10 hidden items-center gap-3 border-b border-hair bg-ink-950/90 px-6 py-3 backdrop-blur md:flex">
          <h1 className="text-sm font-semibold tracking-tight text-zinc-100">{activeLabel}</h1>
          {DOMAIN_SCOPED.includes(active) && domains.length > 0 && (
            <div className="ml-auto flex items-center gap-2 text-sm">
              <span className="text-zinc-400">Target</span>
              <select
                value={selectedId ?? ''}
                onChange={(e) => select(Number(e.target.value))}
                className="rounded-lg border border-hair bg-ink-850 px-3 py-1.5 text-sm outline-none transition hover:border-hair-strong focus:border-accent-500"
              >
                {domains.map((d) => (
                  <option key={d.id} value={d.id}>
                    {d.host} ({d.mode === 'active_authorized' ? 'active' : 'passive'})
                  </option>
                ))}
              </select>
            </div>
          )}
        </div>

        <div className="p-4 md:p-6">
        {/* Mobile target switcher — the top bar is desktop-only, so keep an inline
            picker on small screens. */}
        {DOMAIN_SCOPED.includes(active) && domains.length > 0 && (
          <div className="mb-4 flex items-center gap-2 text-sm md:hidden">
            <span className="text-zinc-400">Target</span>
            <select
              value={selectedId ?? ''}
              onChange={(e) => select(Number(e.target.value))}
              className="rounded-lg border border-hair bg-ink-850 px-3 py-1.5 text-sm outline-none transition hover:border-hair-strong focus:border-accent-500"
            >
              {domains.map((d) => (
                <option key={d.id} value={d.id}>
                  {d.host} ({d.mode === 'active_authorized' ? 'active' : 'passive'})
                </option>
              ))}
            </select>
          </div>
        )}

        <ErrorBoundary key={active}>
          {active === 'home' && <Home navigate={navigate} />}
          {active === 'domains' && <Domains />}
          {active === 'intel' && <Intel navigate={navigate} />}
          {active === 'methodology' && <Methodology />}
          {active === 'subdomains' && <Subdomains />}
          {active === 'screenshots' && <Screenshots />}
          {active === 'fuzzing' && <Fuzzing />}
          {active === 'replay' && <Replay />}
          {active === 'traffic' && <Traffic navigate={navigate} />}
          {active === 'exposure' && <Exposure />}
          {active === 'ports' && <Ports />}
          {active === 'api' && <ApiSurface navigate={navigate} />}
          {active === 'osint' && <Osint />}
          {active === 'social' && <SocialForensics />}
          {active === 'leaks' && <DataLeaks />}
          {active === 'origin' && <Origin />}
          {active === 'whois' && <Whois />}
          {active === 'checkhost' && <CheckHost />}
          {active === 'scans' && <Scans />}
          {active === 'tools' && <Tools />}
          {active === 'owasp' && <Owasp />}
          {active === 'llm' && <LlmSecurity />}
          {active === 'findings' && <Findings navigate={navigate} />}
          {active === 'notes' && <Notes />}
          {active === 'canvas' && <Canvas />}
          {active === 'jobs' && <Jobs />}
          {active === 'audit' && <Audit />}
          {active === 'settings' && <Settings totpEnabled={me.user.totpEnabled} />}
        </ErrorBoundary>
        </div>
      </main>

      <CommandPalette
        open={paletteOpen}
        onClose={() => setPaletteOpen(false)}
        modules={MODULE_INDEX}
        domains={domains}
        navigate={navigate}
      />
    </div>
  )
}
