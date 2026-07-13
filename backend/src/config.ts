import 'dotenv/config'

function required(name: string, value: string | undefined): string {
  if (!value || value.trim() === '') {
    throw new Error(`Missing required env var ${name}. See .env.example.`)
  }
  return value
}

const NODE_ENV = process.env.NODE_ENV ?? 'development'
const isProd = NODE_ENV === 'production'

const SESSION_SECRET = required('SESSION_SECRET', process.env.SESSION_SECRET)
if (SESSION_SECRET.length < 32) {
  throw new Error('SESSION_SECRET must be at least 32 characters.')
}

// Admin creds are OPTIONAL at boot — they are only needed to seed the operator
// on first run. Once the operator exists, the credential lives as an argon2 hash
// in the DB and these env vars can (and should) be removed from .env.
const ADMIN_USERNAME = process.env.ADMIN_USERNAME?.trim() ?? ''
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD ?? ''

// The capture ingest token is the sole authority for the extension endpoints, so
// a weak value lets anyone who guesses it enumerate targets + inject captures.
const CAPTURE_TOKEN = process.env.CAPTURE_TOKEN?.trim() || ''
if (CAPTURE_TOKEN && CAPTURE_TOKEN.length < 16) {
  console.warn('⚠ CAPTURE_TOKEN is short (<16 chars). Use a long random value (e.g. `openssl rand -base64 24`).')
}

export const config = {
  nodeEnv: NODE_ENV,
  isProd,
  port: Number(process.env.PORT ?? 3001),
  host: process.env.HOST ?? '0.0.0.0',
  databasePath: process.env.DATABASE_PATH ?? './data/app.db',
  sessionSecret: SESSION_SECRET,
  admin: {
    username: ADMIN_USERNAME,
    password: ADMIN_PASSWORD,
    configured: Boolean(ADMIN_USERNAME && ADMIN_PASSWORD),
    // Warn (not fail) if the seed password is still the placeholder.
    isDefaultPassword: ADMIN_PASSWORD === 'change-me',
  },
  // Session lifetime: 7 days.
  sessionMaxAgeMs: 7 * 24 * 60 * 60 * 1000,

  // Discord webhook for alerts. Empty => alerting disabled (silent).
  discordWebhookUrl: process.env.DISCORD_WEBHOOK_URL?.trim() || '',

  // Finding scorer provider. Only 'rules' is implemented; 'ollama' is a
  // disabled placeholder interface. Unknown values fall back to 'rules'.
  aiProvider: ((): 'rules' | 'ollama' => {
    const v = process.env.AI_PROVIDER?.trim() || 'rules'
    if (v !== 'rules' && v !== 'ollama') {
      console.warn(`AI_PROVIDER="${v}" is not recognized; defaulting to "rules".`)
      return 'rules'
    }
    return v
  })(),

  // Subdomain discovery scheduler. 0 disables it (manual runs only). Minutes.
  scheduleSubdomainsMinutes: ((): number => {
    const n = Number(process.env.SCHEDULE_SUBDOMAINS_MINUTES ?? 0)
    if (!Number.isFinite(n) || n < 0) {
      console.warn('SCHEDULE_SUBDOMAINS_MINUTES is not a valid non-negative number; disabling scheduler.')
      return 0
    }
    return n
  })(),

  // Optional passphrase for encrypted DB backups. If unset, the backup route
  // requires the passphrase to be supplied in the request.
  backupPassphrase: process.env.BACKUP_PASSPHRASE?.trim() || '',

  // Shared secret the browser-capture extension presents to POST /api/capture.
  // The dashboard is tailnet-only and the ingest route can't use the session
  // cookie (the extension is a different origin + sameSite=strict), so it
  // authenticates with this token instead. Empty => capture ingest DISABLED
  // (the route 503s), so capture is off unless you deliberately set a token.
  captureToken: CAPTURE_TOKEN,

  // Optional LLM for DRAFTING report narrative only (never scoring — scores stay
  // deterministic). Provider-agnostic: any OpenAI-compatible /chat/completions
  // endpoint. Default OFF; point LLM_BASE_URL at Groq / Gemini / a local Ollama.
  // e.g. LLM_BASE_URL=https://api.groq.com/openai/v1  LLM_MODEL=llama-3.3-70b-versatile
  llm: ((): { baseUrl: string; apiKey: string; model: string; enabled: boolean } => {
    const baseUrl = process.env.LLM_BASE_URL?.trim().replace(/\/$/, '') || ''
    const apiKey = process.env.LLM_API_KEY?.trim() || ''
    const model = process.env.LLM_MODEL?.trim() || ''
    return { baseUrl, apiKey, model, enabled: Boolean(baseUrl && model) }
  })(),

  // Optional breach-data provider for the domain leak check (Social/Data Leaks).
  // Default OFF — set LEAK_PROVIDER (hibp | dehashed | leakcheck) + LEAK_API_KEY.
  // Queries the provider's API by domain for exposed accounts. Active domains get
  // an automatic daily check; passive domains are manual only.
  leaks: ((): { provider: '' | 'hibp' | 'dehashed' | 'leakcheck'; apiKey: string; enabled: boolean } => {
    const raw = process.env.LEAK_PROVIDER?.trim().toLowerCase() || ''
    const provider = raw === 'hibp' || raw === 'dehashed' || raw === 'leakcheck' ? raw : ''
    if (raw && !provider) console.warn(`LEAK_PROVIDER="${raw}" is not recognized (use hibp | dehashed | leakcheck); leak checks disabled.`)
    const apiKey = process.env.LEAK_API_KEY?.trim() || ''
    return { provider, apiKey, enabled: Boolean(provider && apiKey) }
  })(),
} as const
