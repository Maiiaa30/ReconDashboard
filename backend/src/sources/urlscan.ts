import { getJson } from '../util/http'

// Passive intel via urlscan.io's public search API (no key). Returns recent
// public scans of the domain — page URLs and screenshot links — a quick way to
// see what's been observed live.
// https://urlscan.io/docs/search/

export interface UrlscanPage {
  url: string
  time: string | null
  screenshot: string | null
}

export interface UrlscanResult {
  count: number
  pages: UrlscanPage[]
}

interface SearchRow {
  page?: { url?: string }
  task?: { time?: string }
  screenshot?: string
}

export async function urlscanSearch(domain: string): Promise<UrlscanResult> {
  const url = `https://urlscan.io/api/v1/search/?q=domain:${encodeURIComponent(domain)}&size=100`
  const data = await getJson<{ results?: SearchRow[]; total?: number }>(url, { timeoutMs: 15_000 })
  const results = Array.isArray(data.results) ? data.results : []
  const pages: UrlscanPage[] = []
  for (const r of results) {
    const u = r.page?.url
    if (u) pages.push({ url: u, time: r.task?.time ?? null, screenshot: r.screenshot ?? null })
    if (pages.length >= 50) break
  }
  return { count: data.total ?? results.length, pages }
}
