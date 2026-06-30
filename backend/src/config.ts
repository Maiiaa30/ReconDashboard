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

const ADMIN_USERNAME = required('ADMIN_USERNAME', process.env.ADMIN_USERNAME)
const ADMIN_PASSWORD = required('ADMIN_PASSWORD', process.env.ADMIN_PASSWORD)

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
} as const
