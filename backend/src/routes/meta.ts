import { readdirSync, statSync } from 'node:fs'
import { join } from 'node:path'
import type { FastifyPluginAsync } from 'fastify'
import { config } from '../config'
import { getScorer } from '../scoring'
import { toolExists } from '../util/exec'

// Lightweight capability/status endpoint so the UI can adapt (e.g. show which
// active scanners are installed, the scorer in use, scheduler state).
let toolCache: Record<string, boolean> | null = null
// Wordlists only change when the image is rebuilt (which restarts this process),
// so scan the dir once instead of on every /meta/status call (~8 pages hit it).
let wordlistCache: ReturnType<typeof listWordlists> | null = null

const WORDLIST_DIR = '/usr/share/wordlists'

// Names that hold fuzzing VALUES (Intruder payloads) vs content-discovery paths.
const PAYLOAD_RE = /(user|pass|cred|sqli|xss|lfi|inject|command|number|auth)/i

// Discover installed wordlists so the Fuzzing/Intruder UIs can offer a real
// picker, tagged so the Intruder can group payload lists apart from path lists.
function listWordlists(): { path: string; name: string; sizeKb: number; category: 'payload' | 'content' }[] {
  try {
    return readdirSync(WORDLIST_DIR)
      .filter((f) => f.endsWith('.txt'))
      .map((f) => {
        const path = join(WORDLIST_DIR, f)
        let sizeKb = 0
        try {
          sizeKb = Math.round(statSync(path).size / 1024)
        } catch {
          /* ignore */
        }
        return { path, name: f, sizeKb, category: (PAYLOAD_RE.test(f) ? 'payload' : 'content') as 'payload' | 'content' }
      })
      .sort((a, b) => a.sizeKb - b.sizeKb)
  } catch {
    return []
  }
}

export const metaRoutes: FastifyPluginAsync = async (app) => {
  app.get('/api/meta/status', async () => {
    if (!toolCache) {
      const [subfinder, nmap, nuclei, ffuf, chromium, dig, katana, naabu, dalfox, sslscan, sqlmap] = await Promise.all([
        toolExists('subfinder'),
        toolExists('nmap'),
        toolExists('nuclei'),
        toolExists('ffuf'),
        toolExists(process.env.CHROMIUM_PATH ?? 'chromium'),
        toolExists('dig'),
        toolExists('katana'),
        toolExists('naabu'),
        toolExists('dalfox'),
        toolExists('sslscan'),
        toolExists('sqlmap'),
      ])
      // wpenum + bypass403 + methods + datastores are HTTP routines (no binary) — always available.
      toolCache = { subfinder, nmap, nuclei, ffuf, chromium, dig, katana, naabu, dalfox, sslscan, sqlmap, wpenum: true, bypass403: true, methods: true, datastores: true }
    }
    return {
      scorer: getScorer().name,
      aiProvider: config.aiProvider,
      scheduler: {
        enabled: config.scheduleSubdomainsMinutes > 0,
        intervalMinutes: config.scheduleSubdomainsMinutes,
      },
      discordConfigured: Boolean(config.discordWebhookUrl),
      llm: { enabled: config.llm.enabled, model: config.llm.enabled ? config.llm.model : null },
      leaks: { enabled: config.leaks.enabled, provider: config.leaks.enabled ? config.leaks.provider : null },
      tools: toolCache,
      wordlists: (wordlistCache ??= listWordlists()),
    }
  })
}
