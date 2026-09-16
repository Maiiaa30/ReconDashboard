import { XMLParser } from 'fast-xml-parser'
import { addScoredFinding } from './score'
import { type FindingType } from './store'

// Import scan output produced OUTSIDE the dashboard (a Nuclei/Nmap run on the
// operator's own box, or a generic findings export) into a domain's findings,
// so the dashboard is not a data silo. Imported items are mapped to the SAME
// finding shapes the native scanners produce, so they dedup against native
// results (findingKey) and render/score/export identically. Everything imported
// carries an `imported: true` marker and an `imported` tag for provenance.

export type ImportFormat = 'nuclei' | 'nmap' | 'findings'

// A parsed, not-yet-persisted finding. Kept separate from persistence so the
// parsers stay pure and unit-testable without a database.
export interface ImportItem {
  type: FindingType
  data: Record<string, unknown>
  tags: string[]
}

export interface ImportResult {
  format: ImportFormat
  parsed: number // items the parser produced
  imported: number // items actually written
  skipped: number // malformed/invalid items dropped
  errors: string[] // up to a few human-readable parse notes
}

// Cap to keep a hostile or huge upload from ballooning the DB in one request.
const MAX_ITEMS = 5000
const VALID_TYPES = new Set<string>([
  'new_subdomain', 'exposure', 'osint', 'nmap', 'nuclei', 'ffuf', 'origin', 'owasp',
  'tool', 'cve_new', 'leak', 'api', 'secret', 'authz', 'param', 'asset_change',
])

const arr = <T>(v: T | T[] | undefined | null): T[] => (Array.isArray(v) ? v : v == null ? [] : [v])

// Best-effort host from a nuclei "matched-at" (often a URL, sometimes host:port).
function hostOf(matched: string | undefined, fallback: string | undefined): string | undefined {
  if (!matched) return fallback
  try {
    return new URL(matched).hostname || fallback
  } catch {
    return matched.split('/')[0]?.split(':')[0] || fallback
  }
}

// --- Nuclei JSONL ------------------------------------------------------------
// One JSON object per line (nuclei -jsonl). Mirrors the native nuclei mapping.
export function parseNucleiJsonl(content: string): { items: ImportItem[]; skipped: number; errors: string[] } {
  const items: ImportItem[] = []
  const errors: string[] = []
  let skipped = 0
  const lines = content.split('\n')
  for (const line of lines) {
    const t = line.trim()
    if (!t) continue
    let r: Record<string, unknown>
    try {
      r = JSON.parse(t)
    } catch {
      skipped++
      if (errors.length < 5) errors.push(`unparseable JSONL line: ${t.slice(0, 80)}`)
      continue
    }
    const info = (r.info ?? {}) as Record<string, unknown>
    const matched = (r['matched-at'] ?? r.matched) as string | undefined
    const host = (r.host as string | undefined) ?? hostOf(matched, undefined)
    const templateId = (r['template-id'] ?? r.templateID) as string | undefined
    if (!templateId && !matched) {
      skipped++
      continue
    }
    items.push({
      type: 'nuclei',
      data: {
        target: host ?? null,
        templateId: templateId ?? null,
        name: info.name ?? null,
        severity: info.severity ?? null,
        matched: matched ?? null,
        info,
        imported: true,
      },
      tags: ['nuclei', 'imported'],
    })
    if (items.length >= MAX_ITEMS) break
  }
  return { items, skipped, errors }
}

// --- Nmap XML ----------------------------------------------------------------
// `nmap -oX`. One 'nmap' finding per host, same port shape the native scanner
// writes so the Ports view and dedup work unchanged.
export function parseNmapXml(content: string): { items: ImportItem[]; skipped: number; errors: string[] } {
  const errors: string[] = []
  let parsed: any
  try {
    parsed = new XMLParser({ ignoreAttributes: false, attributeNamePrefix: '@_' }).parse(content)
  } catch (err) {
    return { items: [], skipped: 0, errors: [`nmap XML parse failed: ${(err as Error).message}`] }
  }
  const hosts = arr(parsed?.nmaprun?.host)
  const items: ImportItem[] = []
  let skipped = 0
  const KEEP = new Set(['open', 'filtered'])
  for (const h of hosts) {
    const addresses = arr(h?.address).map((a: any) => a?.['@_addr']).filter(Boolean)
    const hostnames = arr(h?.hostnames?.hostname).map((n: any) => n?.['@_name']).filter(Boolean)
    const target = hostnames[0] ?? addresses[0]
    if (!target) {
      skipped++
      continue
    }
    const allPorts = arr(h?.ports?.port)
      .filter((p: any) => KEEP.has(p?.state?.['@_state']))
      .map((p: any) => {
        const svc = p?.service ?? {}
        return {
          port: Number(p['@_portid']),
          protocol: String(p['@_protocol'] ?? 'tcp'),
          state: String(p?.state?.['@_state'] ?? 'open'),
          service: svc['@_name'] ?? null,
          product: svc['@_product'] ?? null,
          version: svc['@_version'] ?? null,
          extrainfo: svc['@_extrainfo'] ?? null,
        }
      })
    const openPorts = allPorts.filter((p) => p.state === 'open')
    items.push({
      type: 'nmap',
      data: { target, deep: false, openPorts, allPorts, ip: addresses[0] ?? null, imported: true },
      tags: ['nmap', 'imported'],
    })
    if (items.length >= MAX_ITEMS) break
  }
  return { items, skipped, errors }
}

// --- Generic findings JSON ---------------------------------------------------
// An array of { type, data, tags? } (e.g. this dashboard's own JSON export, or a
// hand-rolled bundle). Only known finding types with an object `data` are kept.
export function parseFindingsJson(content: string): { items: ImportItem[]; skipped: number; errors: string[] } {
  let root: unknown
  try {
    root = JSON.parse(content)
  } catch (err) {
    return { items: [], skipped: 0, errors: [`findings JSON parse failed: ${(err as Error).message}`] }
  }
  // Accept a bare array or a { findings: [...] } envelope (our export shape).
  const list = Array.isArray(root)
    ? root
    : Array.isArray((root as { findings?: unknown }).findings)
      ? (root as { findings: unknown[] }).findings
      : null
  if (!list) return { items: [], skipped: 0, errors: ['expected an array or { findings: [...] }'] }

  const items: ImportItem[] = []
  const errors: string[] = []
  let skipped = 0
  for (const raw of list) {
    const f = raw as { type?: unknown; data?: unknown; tags?: unknown }
    const type = String(f.type ?? '')
    if (!VALID_TYPES.has(type) || !f.data || typeof f.data !== 'object' || Array.isArray(f.data)) {
      skipped++
      if (errors.length < 5) errors.push(`skipped item with type "${type || '(none)'}"`)
      continue
    }
    const tags = Array.isArray(f.tags) ? f.tags.map(String) : []
    items.push({
      type: type as FindingType,
      data: { ...(f.data as Record<string, unknown>), imported: true },
      tags: [...new Set([...tags, 'imported'])],
    })
    if (items.length >= MAX_ITEMS) break
  }
  return { items, skipped, errors }
}

function parse(format: ImportFormat, content: string) {
  switch (format) {
    case 'nuclei':
      return parseNucleiJsonl(content)
    case 'nmap':
      return parseNmapXml(content)
    case 'findings':
      return parseFindingsJson(content)
  }
}

/**
 * Parse `content` in the given format and persist each item as a scored finding
 * on `domainId`. Items dedup against native scans via findingKey (same shapes).
 */
export async function importScanData(domainId: number, format: ImportFormat, content: string): Promise<ImportResult> {
  const { items, skipped, errors } = parse(format, content)
  let imported = 0
  for (const item of items) {
    try {
      await addScoredFinding({ domainId, type: item.type, data: item.data, tags: item.tags })
      imported++
    } catch (err) {
      if (errors.length < 5) errors.push(`failed to store a ${item.type} item: ${(err as Error).message}`)
    }
  }
  return { format, parsed: items.length, imported, skipped, errors }
}
