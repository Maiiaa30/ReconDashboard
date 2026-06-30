import type { FastifyPluginAsync } from 'fastify'
import { config } from '../config'
import { getScorer } from '../scoring'
import { toolExists } from '../util/exec'

// Lightweight capability/status endpoint so the UI can adapt (e.g. show which
// active scanners are installed, the scorer in use, scheduler state).
let toolCache: Record<string, boolean> | null = null

export const metaRoutes: FastifyPluginAsync = async (app) => {
  app.get('/api/meta/status', async () => {
    if (!toolCache) {
      const [subfinder, nmap, nuclei, ffuf] = await Promise.all([
        toolExists('subfinder'),
        toolExists('nmap'),
        toolExists('nuclei'),
        toolExists('ffuf'),
      ])
      toolCache = { subfinder, nmap, nuclei, ffuf }
    }
    return {
      scorer: getScorer().name,
      aiProvider: config.aiProvider,
      scheduler: {
        enabled: config.scheduleSubdomainsMinutes > 0,
        intervalMinutes: config.scheduleSubdomainsMinutes,
      },
      discordConfigured: Boolean(config.discordWebhookUrl),
      tools: toolCache,
    }
  })
}
