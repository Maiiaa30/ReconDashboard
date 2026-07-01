import { config } from '../config'

// Batched Discord webhook alerts. If no webhook is configured, every call is a
// silent no-op (never throws, never blocks a job). Messages are chunked to stay
// under Discord's 2000-character content limit and grouped to avoid spam.

const MAX_CONTENT = 1900

async function postContent(content: string): Promise<void> {
  if (!config.discordWebhookUrl) return
  const controller = new AbortController()
  const timer = setTimeout(() => controller.abort(), 10_000)
  try {
    await fetch(config.discordWebhookUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ content }),
      signal: controller.signal,
    })
  } catch {
    // Best-effort; alerting must never break a recon job.
  } finally {
    clearTimeout(timer)
  }
}

/** Send a titled, grouped alert for a list of lines (e.g. new subdomains). */
export async function alertList(title: string, lines: string[]): Promise<void> {
  if (!config.discordWebhookUrl || lines.length === 0) return

  const header = `**${title}**`
  let buf = header
  for (const line of lines) {
    const next = `${buf}\n• ${line}`
    if (next.length > MAX_CONTENT) {
      await postContent(buf)
      buf = `${header} (cont.)\n• ${line}`
    } else {
      buf = next
    }
  }
  if (buf !== header) await postContent(buf)
}

export async function alertText(text: string): Promise<void> {
  if (!config.discordWebhookUrl) return
  await postContent(text.slice(0, MAX_CONTENT))
}

/** True if a Discord webhook is configured. */
export function isDiscordConfigured(): boolean {
  return Boolean(config.discordWebhookUrl)
}

// Like postContent but reports whether Discord accepted the message — used by
// the on-demand "send note" action so the operator gets real feedback.
async function postContentChecked(content: string): Promise<boolean> {
  if (!config.discordWebhookUrl) return false
  const controller = new AbortController()
  const timer = setTimeout(() => controller.abort(), 10_000)
  try {
    const res = await fetch(config.discordWebhookUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ content }),
      signal: controller.signal,
    })
    return res.ok
  } catch {
    return false
  } finally {
    clearTimeout(timer)
  }
}

/** Push a note (title + body) to the webhook, chunked. Reports success. */
export async function sendNoteToDiscord(
  title: string | null,
  body: string | null,
): Promise<{ ok: boolean; reason?: string }> {
  if (!config.discordWebhookUrl) return { ok: false, reason: 'no Discord webhook configured' }
  const heading = title?.trim() ? `**Note — ${title.trim()}**` : '**Note**'
  const text = body?.trim() ? `${heading}\n${body.trim()}` : heading
  let failed = false
  for (let i = 0; i < text.length; i += MAX_CONTENT) {
    if (!(await postContentChecked(text.slice(i, i + MAX_CONTENT)))) failed = true
  }
  return failed ? { ok: false, reason: 'Discord rejected the message' } : { ok: true }
}

export interface SubdomainAlert {
  host: string
  status: number | null
  title: string | null
  server: string | null
  ip: string | null
}

// Rich alert for new subdomains: status code, page title, server, IP.
export async function alertSubdomains(title: string, items: SubdomainAlert[]): Promise<void> {
  if (!config.discordWebhookUrl || items.length === 0) return

  const lines = items.map((s) => {
    const status = s.status != null ? `\`${s.status}\`` : '`—`'
    const parts = [`${status} **${s.host}**`]
    if (s.title) parts.push(`— ${s.title.slice(0, 80)}`)
    const meta: string[] = []
    if (s.ip) meta.push(s.ip)
    if (s.server) meta.push(s.server)
    if (meta.length) parts.push(`(${meta.join(', ')})`)
    return parts.join(' ')
  })

  const header = `**${title}**`
  let buf = header
  for (const line of lines) {
    const next = `${buf}\n${line}`
    if (next.length > MAX_CONTENT) {
      await postContent(buf)
      buf = `${header} (cont.)\n${line}`
    } else {
      buf = next
    }
  }
  if (buf !== header) await postContent(buf)
}
