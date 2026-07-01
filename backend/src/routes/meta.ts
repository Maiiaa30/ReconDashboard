import { readdirSync, statSync } from 'node:fs'
import { join } from 'node:path'
import type { FastifyPluginAsync } from 'fastify'
import { config } from '../config'
import { getScorer } from '../scoring'
import { toolExists } from '../util/exec'

// Lightweight capability/status endpoint so the UI can adapt (e.g. show which
// active scanners are installed, the scorer in use, scheduler state).
let toolCache: Record<string, boolean> | null = null

const WORDLIST_DIR = '/usr/share/wordlists'

// Discover installed wordlists so the Fuzzing UI can offer a real picker.
function listWordlists(): { path: string; name: string; sizeKb: number }[] {
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
        return { path, name: f, sizeKb }
      })
      .sort((a, b) => a.sizeKb - b.sizeKb)
  } catch {
    return []
  }
}

export const metaRoutes: FastifyPluginAsync = async (app) => {
  app.get('/api/meta/status', async () => {
    if (!toolCache) {
      const [subfinder, nmap, nuclei, ffuf, chromium, dig, katana, naabu, dalfox, sslscan] = await Promise.all([
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
      ])
      // wpenum is an HTTP routine (no binary) — always available.
      toolCache = { subfinder, nmap, nuclei, ffuf, chromium, dig, katana, naabu, dalfox, sslscan, wpenum: true }
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
      tools: toolCache,
      wordlists: listWordlists(),
    }
  })
}
