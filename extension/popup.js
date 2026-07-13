// Popup: configure the dashboard URL + capture token, toggle capture on/off, and
// test the connection. Config lives in extension storage; the background service
// worker reads it and reacts to changes.
const api = globalThis.browser ?? chrome
const $ = (id) => document.getElementById(id)

function setStatus(text) {
  $('status').textContent = text
}

function setDot(on) {
  $('dot').classList.toggle('on', !!on)
}

async function load() {
  const { config } = await api.storage.local.get('config')
  const c = config || {}
  $('url').value = c.dashboardUrl || ''
  $('token').value = c.token || ''
  $('enabled').checked = !!c.enabled
  $('assets').checked = !!c.captureAssets
  setDot(c.enabled)
}

async function test() {
  const url = $('url').value.trim().replace(/\/+$/, '')
  const token = $('token').value.trim()
  if (!url || !token) return setStatus('Enter the dashboard URL and token.')
  setStatus('Testing…')
  try {
    const res = await fetch(url + '/api/capture/targets', { headers: { 'X-Capture-Token': token } })
    if (res.ok) {
      const j = await res.json()
      const n = Array.isArray(j.hosts) ? j.hosts.length : 0
      setStatus(`Connected — capturing ${n} target host(s).`)
    } else if (res.status === 401) {
      setStatus('Invalid token.')
    } else if (res.status === 503) {
      setStatus('Capture is disabled on the server (set CAPTURE_TOKEN).')
    } else {
      setStatus('Server responded ' + res.status + '.')
    }
  } catch {
    setStatus('Cannot reach the dashboard at that URL.')
  }
}

async function save() {
  const config = {
    dashboardUrl: $('url').value.trim(),
    token: $('token').value.trim(),
    enabled: $('enabled').checked,
    captureAssets: $('assets').checked,
  }
  await api.storage.local.set({ config })
  setDot(config.enabled)
  await test()
}

$('save').addEventListener('click', save)
$('enabled').addEventListener('change', () => setDot($('enabled').checked))
load().then(test)
