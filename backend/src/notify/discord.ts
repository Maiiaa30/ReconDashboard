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
