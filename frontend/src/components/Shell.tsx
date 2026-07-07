import { useEffect, useState } from 'react'
import {
  Home as HomeIcon, Globe, Brain, Network, Camera, Crosshair, Radar, Eye, ShieldAlert, FileText,
  Activity, ScanSearch, ShieldCheck, Flag, StickyNote, PenTool, ScrollText,
  Settings as SettingsIcon, LogOut, Menu, X, Search, Radar as RadarLogo, Wrench, History, ListChecks, Bot, Fingerprint, DatabaseZap, type LucideIcon,
} from 'lucide-react'
import { CommandPalette } from './CommandPalette'
import type { Me } from '../api'
import { api } from '../api'
import { useApp } from '../state'
import { Domains } from '../pages/Domains'
import { Intel } from '../pages/Intel'
import { Methodology } from '../pages/Methodology'
import { Subdomains } from '../pages/Subdomains'
import { Screenshots } from '../pages/Screenshots'
import { Fuzzing } from '../pages/Fuzzing'
import { Exposure } from '../pages/Exposure'
import { Osint } from '../pages/Osint'
import { SocialForensics } from '../pages/SocialForensics'
import { DataLeaks } from '../pages/DataLeaks'
import { Origin } from '../pages/Origin'
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
const DOMAIN_SCOPED: ModuleKey[] = ['intel', 'methodology', 'subdomains', 'screenshots', 'fuzzing', 'exposure', 'osint', 'leaks', 'origin', 'scans', 'tools', 'owasp', 'notes']

export function Shell({ me, onLogout }: { me: Me; onLogout: () => void }) {
  const { domains, selectedId, select } = useApp()
  const [active, setActive] = useState<ModuleKey>('home')
  const [navOpen, setNavOpen] = useState(false)
  const [paletteOpen, setPaletteOpen] = useState(false)
  const activeLabel = MODULES.find((m) => m.key === active)?.label ?? 'Recon Dashboard'

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
        className={`fixed inset-y-0 left-0 z-40 flex w-64 flex-col border-r border-hair bg-ink-900 transition-transform duration-200 ease-out md:sticky md:top-0 md:z-auto md:h-screen md:w-56 md:translate-x-0 ${
          navOpen ? 'translate-x-0' : '-translate-x-full'
        }`}
      >
        <div className="flex items-center gap-2.5 px-4 py-4">
          <span className="flex h-8 w-8 items-center justify-center rounded-lg bg-accent-500 shadow-sm shadow-accent-500/30">
            <RadarLogo size={18} className="text-white" />
          </span>
          <div className="min-w-0 flex-1">
            <div className="truncate text-sm font-semibold tracking-tight">Recon Dashboard</div>
            <div className="truncate text-xs text-zinc-500">{me.user.username}</div>
          </div>
          <button
            onClick={() => setNavOpen(false)}
            aria-label="Close menu"
            className="text-zinc-500 transition hover:text-zinc-200 md:hidden"
          >
            <X size={18} />
          </button>
        </div>
        <button
          onClick={() => {
            setPaletteOpen(true)
            setNavOpen(false)
          }}
          className="mx-2 mb-1 flex items-center gap-2 rounded-lg border border-hair bg-ink-850 px-3 py-2 text-sm text-zinc-500 transition hover:border-hair-strong hover:text-zinc-300"
        >
          <Search size={15} />
          <span className="flex-1 text-left">Search…</span>
          <kbd className="rounded bg-ink-800 px-1.5 py-0.5 text-[10px]">⌘K</kbd>
        </button>
        <nav className="flex-1 overflow-y-auto px-2 pb-2">
          {NAV_SECTIONS.map((section) => (
            <div key={section.title}>
              <div className="px-3 pb-1 pt-3 text-[11px] font-semibold uppercase tracking-wider text-zinc-500">
                {section.title}
              </div>
              {section.items.map((m) => {
                const Icon = m.icon
                const isActive = active === m.key
                return (
                  <button
                    key={m.key}
                    onClick={() => {
                      setActive(m.key)
                      setNavOpen(false)
                    }}
                    className={`flex w-full items-center gap-2.5 rounded-lg px-3 py-2 text-left text-sm transition ${
                      isActive
                        ? 'bg-accent-500/15 font-medium text-accent-fg'
                        : 'text-zinc-400 hover:bg-ink-800 hover:text-zinc-200'
                    }`}
                  >
                    <Icon size={17} className={isActive ? 'text-accent-400' : 'text-zinc-500'} />
                    {m.label}
                  </button>
                )
              })}
            </div>
          ))}
        </nav>
        <div className="border-t border-hair p-2">
          <button
            onClick={logout}
            className="flex w-full items-center gap-2.5 rounded-lg px-3 py-2 text-left text-sm text-zinc-400 hover:bg-ink-800 hover:text-zinc-200"
          >
            <LogOut size={17} className="text-zinc-500" /> Log out
          </button>
        </div>
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

        {active === 'home' && <Home navigate={navigate} />}
        {active === 'domains' && <Domains />}
        {active === 'intel' && <Intel />}
        {active === 'methodology' && <Methodology />}
        {active === 'subdomains' && <Subdomains />}
        {active === 'screenshots' && <Screenshots />}
        {active === 'fuzzing' && <Fuzzing />}
        {active === 'exposure' && <Exposure />}
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
        {active === 'findings' && <Findings />}
        {active === 'notes' && <Notes />}
        {active === 'canvas' && <Canvas />}
        {active === 'jobs' && <Jobs />}
        {active === 'audit' && <Audit />}
        {active === 'settings' && <Settings totpEnabled={me.user.totpEnabled} />}
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
