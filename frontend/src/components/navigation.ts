import {
  Activity, Bot, Boxes, Brain, BriefcaseBusiness, Camera, Crosshair, DatabaseZap, Eye, FileCheck2,
  FileText, Fingerprint, Flag, Globe, History, Home, ListChecks, Network, PenTool, Radar, Radio,
  Repeat, Router, ScanSearch, ScrollText, Settings, ShieldAlert, ShieldCheck, StickyNote, Webhook,
  Wrench, type LucideIcon,
} from 'lucide-react'

export interface NavItem {
  key: string
  label: string
  icon: LucideIcon
}

export interface NavSection {
  title: string
  icon: LucideIcon
  primary?: boolean
  items: NavItem[]
}

export const NAV_SECTIONS: NavSection[] = [
  {
    title: 'Workflow',
    icon: BriefcaseBusiness,
    primary: true,
    items: [
      { key: 'home', label: 'Portfolio', icon: Home },
      { key: 'command', label: 'Command Center', icon: BriefcaseBusiness },
      { key: 'actions', label: 'Next Actions', icon: ListChecks },
      { key: 'domains', label: 'Scope & Targets', icon: Globe },
      { key: 'assets', label: 'Asset Inventory', icon: Boxes },
      { key: 'runs', label: 'Assessment Runs', icon: History },
      { key: 'findings', label: 'Findings', icon: Flag },
      { key: 'reports', label: 'Reports', icon: FileCheck2 },
    ],
  },
  {
    title: 'Intelligence',
    icon: Eye,
    items: [
      { key: 'subdomains', label: 'Subdomains', icon: Network },
      { key: 'screenshots', label: 'Screenshots', icon: Camera },
      { key: 'exposure', label: 'Exposure', icon: Radar },
      { key: 'ports', label: 'Ports', icon: Router },
      { key: 'api', label: 'API Surface', icon: Webhook },
      { key: 'osint', label: 'OSINT', icon: Eye },
      { key: 'social', label: 'Social Forensics', icon: Fingerprint },
      { key: 'leaks', label: 'Data Leaks', icon: DatabaseZap },
      { key: 'whois', label: 'WHOIS', icon: FileText },
      { key: 'checkhost', label: 'Check Host', icon: Activity },
    ],
  },
  {
    title: 'Testing',
    icon: ScanSearch,
    items: [
      { key: 'profiles', label: 'Scan Profiles', icon: Radar },
      { key: 'scans', label: 'Scans', icon: ScanSearch },
      { key: 'fuzzing', label: 'Fuzzing', icon: Crosshair },
      { key: 'tools', label: 'Tools', icon: Wrench },
      { key: 'owasp', label: 'OWASP', icon: ShieldCheck },
      { key: 'origin', label: 'WAF / Origin', icon: ShieldAlert },
      { key: 'llm', label: 'LLM Security', icon: Bot },
    ],
  },
  {
    title: 'HTTP Lab',
    icon: Repeat,
    items: [
      { key: 'traffic', label: 'Traffic', icon: Radio },
      { key: 'replay', label: 'Replay', icon: Repeat },
    ],
  },
  {
    title: 'Workspace',
    icon: Flag,
    items: [
      { key: 'intel', label: 'Attack Paths', icon: Brain },
      { key: 'changes', label: 'Change History', icon: History },
      { key: 'notes', label: 'Notes', icon: StickyNote },
      { key: 'canvas', label: 'Canvas', icon: PenTool },
    ],
  },
  {
    title: 'System',
    icon: Settings,
    items: [
      { key: 'jobs', label: 'Logs', icon: ScrollText },
      { key: 'audit', label: 'Audit', icon: History },
      { key: 'settings', label: 'Settings', icon: Settings },
    ],
  },
]

const HIDDEN_MODULES: NavItem[] = [{ key: 'methodology', label: 'Methodology', icon: ListChecks }]
export const MODULES = [...NAV_SECTIONS.flatMap((section) => section.items), ...HIDDEN_MODULES]
export const MODULE_INDEX = NAV_SECTIONS.flatMap((section) => section.items.map((item) => ({ key: item.key, label: item.label, section: section.title })))
export type ModuleKey = (typeof MODULES)[number]['key']

export const DOMAIN_SCOPED: ModuleKey[] = ['command', 'actions', 'assets', 'profiles', 'runs', 'reports', 'changes', 'intel', 'methodology', 'subdomains', 'screenshots', 'fuzzing', 'replay', 'traffic', 'exposure', 'ports', 'api', 'osint', 'leaks', 'origin', 'scans', 'tools', 'owasp', 'notes']

export function sectionForModule(key: string): NavSection | undefined {
  return NAV_SECTIONS.find((section) => section.items.some((item) => item.key === key))
}

export function readExpandedSections(raw: string | null): Set<string> {
  if (!raw) return new Set()
  try {
    const parsed = JSON.parse(raw)
    if (!Array.isArray(parsed)) return new Set()
    const allowed = new Set(NAV_SECTIONS.filter((section) => !section.primary).map((section) => section.title))
    return new Set(parsed.filter((title): title is string => typeof title === 'string' && allowed.has(title)))
  } catch {
    return new Set()
  }
}
