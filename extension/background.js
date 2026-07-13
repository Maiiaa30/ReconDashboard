// Recon Dashboard capture — MV3 background service worker.
//
// Observes (never blocks) requests via webRequest, and for hosts that belong to
// a tracked domain, ships {method,url,headers,body} to the dashboard's
// /api/capture with the shared CAPTURE_TOKEN. It deliberately captures REQUESTS
// only (no response bodies) — the operator re-sends from the Replay tool. Traffic
// to any host that isn't a tracked target (your email, bank, …) is never sent.

// Cross-browser: Firefox exposes promise-based `browser.*`; Chrome uses `chrome.*`
// (promise-capable in MV3). Prefer browser so `await` works on both.
const api = globalThis.browser ?? chrome
// `extraHeaders` (needed to read Cookie/Authorization) is a Chrome-only extraInfoSpec;
// passing it on Firefox errors, so only include it where supported.
const EXTRA =
  api.webRequest.OnBeforeSendHeadersOptions && api.webRequest.OnBeforeSendHeadersOptions.EXTRA_HEADERS ? ['extraHeaders'] : []

const CONFIG_KEY = 'config'
const MAX_BODY = 200 * 1024

// Only capture request types worth replaying: page/frame navigations, XHR/fetch
// API calls, websockets, and misc fetches. Images, fonts, stylesheets, scripts,
// media, etc. are noise for a request-replay tool and are dropped.
const CAPTURE_TYPES = new Set(['main_frame', 'sub_frame', 'xmlhttprequest', 'websocket', 'other'])
// Backstop: drop asset URLs even if the browser mis-typed the resource.
const ASSET_RE = /\.(png|jpe?g|gif|svg|webp|avif|bmp|ico|woff2?|ttf|otf|eot|css|js|mjs|map|mp4|webm|mp3|wav|ogg|pdf)(\?|#|$)/i

let cfg = { dashboardUrl: '', token: '', enabled: false, captureAssets: false }
let targets = [] // lowercased tracked hostnames, fetched from the dashboard
const pending = new Map() // requestId -> { method, url, type, body }

// MV3 service workers sleep when idle; the request that WAKES the worker (often a
// navigation) fires before config/targets have loaded, so it would be dropped.
// Until ready, we buffer finished captures and flush them once config is in.
let ready = false
const buffer = []
const MAX_BUFFER = 300

function base() {
  return (cfg.dashboardUrl || '').replace(/\/+$/, '')
}
function dashHost() {
  try {
    return new URL(cfg.dashboardUrl).hostname.toLowerCase()
  } catch {
    return ''
  }
}
function hostTracked(host) {
  const h = (host || '').toLowerCase()
  return targets.some((t) => h === t || h.endsWith('.' + t))
}

async function loadConfig() {
  const data = await api.storage.local.get(CONFIG_KEY)
  cfg = Object.assign({ dashboardUrl: '', token: '', enabled: false, captureAssets: false }, data[CONFIG_KEY] || {})
}

// Pull the list of tracked hosts so we only capture in-scope traffic.
async function refreshTargets() {
  if (!cfg.enabled || !cfg.dashboardUrl || !cfg.token) {
    targets = []
    return
  }
  try {
    const res = await fetch(base() + '/api/capture/targets', { headers: { 'X-Capture-Token': cfg.token } })
    if (res.ok) {
      const j = await res.json()
      targets = Array.isArray(j.hosts) ? j.hosts.map((h) => String(h).toLowerCase()) : []
    }
  } catch {
    /* keep the previous list on a transient failure */
  }
}

function decodeBody(details) {
  const rb = details.requestBody
  if (!rb) return null
  if (rb.formData) {
    const parts = []
    for (const k of Object.keys(rb.formData)) {
      for (const v of rb.formData[k]) parts.push(encodeURIComponent(k) + '=' + encodeURIComponent(v))
    }
    return parts.join('&')
  }
  if (rb.raw && rb.raw.length) {
    try {
      const chunks = rb.raw.map((r) => new Uint8Array(r.bytes || []))
      let total = 0
      for (const c of chunks) total += c.length
      const buf = new Uint8Array(Math.min(total, MAX_BODY))
      let off = 0
      for (const c of chunks) {
        if (off >= buf.length) break
        const take = Math.min(c.length, buf.length - off)
        buf.set(c.subarray(0, take), off)
        off += take
      }
      return new TextDecoder('utf-8', { fatal: false }).decode(buf)
    } catch {
      return null
    }
  }
  return null
}

function capturable(rec) {
  if (!cfg.enabled || !cfg.dashboardUrl || !cfg.token) return false
  if (rec.method === 'OPTIONS') return false // CORS preflight noise
  // Drop asset/noise request types (images, fonts, css, scripts, media, …)
  // unless the operator explicitly opted to capture assets.
  if (!cfg.captureAssets && rec.type && !CAPTURE_TYPES.has(rec.type)) return false
  let url
  try {
    url = new URL(rec.url)
    if (url.protocol !== 'http:' && url.protocol !== 'https:') return false
  } catch {
    return false
  }
  if (!cfg.captureAssets && ASSET_RE.test(url.pathname)) return false // backstop for mis-typed assets
  const host = url.hostname.toLowerCase()
  if (host === dashHost()) return false // never capture the dashboard's own traffic
  return hostTracked(host)
}

// Ship if capturable now, or buffer until config is ready (cold-start safety).
function emit(rec) {
  if (ready) {
    if (capturable(rec)) ship(rec)
  } else if (buffer.length < MAX_BUFFER) {
    buffer.push(rec)
  }
}

async function ship(req) {
  try {
    await fetch(base() + '/api/capture', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-Capture-Token': cfg.token },
      body: JSON.stringify({ method: req.method, url: req.url, headers: req.headers, body: req.body }),
    })
  } catch {
    /* best-effort — a dropped capture is not worth surfacing */
  }
}

// Body + method + url + type arrive first. Store for every http(s) request when
// config isn't ready yet (so the wakening request survives), otherwise only when
// it's a keeper — keeps the in-flight map small on busy pages.
api.webRequest.onBeforeRequest.addListener(
  (details) => {
    if (!/^https?:/.test(details.url)) return
    const rec = { method: details.method, url: details.url, type: details.type }
    if (ready && !capturable(rec)) return
    pending.set(details.requestId, { ...rec, body: decodeBody(details) })
  },
  { urls: ['<all_urls>'] },
  ['requestBody'],
)

// …then the final headers (extraHeaders so Cookie/Authorization are visible).
api.webRequest.onBeforeSendHeaders.addListener(
  (details) => {
    const p = pending.get(details.requestId)
    if (!p) return
    pending.delete(details.requestId)
    const headers = (details.requestHeaders || []).map((h) => [h.name, h.value == null ? '' : String(h.value)])
    emit({ method: p.method, url: p.url, type: p.type, headers, body: p.body })
  },
  { urls: ['<all_urls>'] },
  ['requestHeaders', ...EXTRA],
)

// Clean up the map if a request ends without headers ever firing.
const drop = (details) => pending.delete(details.requestId)
api.webRequest.onCompleted.addListener(drop, { urls: ['<all_urls>'] })
api.webRequest.onErrorOccurred.addListener(drop, { urls: ['<all_urls>'] })

api.storage.onChanged.addListener((changes, area) => {
  if (area === 'local' && changes[CONFIG_KEY]) loadConfig().then(refreshTargets)
})

// Refresh the target list periodically (service workers sleep; alarms wake them).
api.alarms.create('refresh-targets', { periodInMinutes: 1 })
api.alarms.onAlarm.addListener((a) => {
  if (a.name === 'refresh-targets') loadConfig().then(refreshTargets)
})

// Cold start: load config + targets, then flush anything buffered while we waited.
async function init() {
  await loadConfig()
  await refreshTargets()
  ready = true
  const held = buffer.splice(0, buffer.length)
  for (const rec of held) if (capturable(rec)) ship(rec)
}
init()
