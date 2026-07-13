# Recon Dashboard — Capture extension

A minimal Chrome (Manifest V3) extension that passively captures **requests** you
make to your **tracked targets** and sends them to the dashboard's
`/api/capture`, where they appear on the **Traffic** page. From there, one click
sends any request into the **Replay** (Repeater) tool.

It captures requests only — never response bodies — and only for hosts that
belong to a tracked domain. All other browsing (email, banking, anything not a
target) is never sent anywhere.

## One-time server setup

1. Set a strong random `CAPTURE_TOKEN` in the dashboard's `.env`:
   ```
   CAPTURE_TOKEN=<long-random-string>
   ```
2. Recreate the backend so it picks up the env var:
   ```
   docker compose up -d backend
   ```
   (Capture is **disabled** until a token is set — the ingest route returns 503.)

## Load the extension

### Chrome / Edge / Brave

1. Open `chrome://extensions`.
2. Turn on **Developer mode** (top-right).
3. Click **Load unpacked** and select this `extension/` folder.

### Firefox (121+)

1. Open `about:debugging#/runtime/this-firefox`.
2. Click **Load Temporary Add-on…** and select this folder's `manifest.json`.
3. If prompted, grant the host permission so it can observe requests.

(Temporary add-ons are removed when Firefox restarts — reload it the same way
next session. The same folder works for both browsers.)

### Then, in either browser

4. Click the extension's icon to open the popup and fill in:
   - **Dashboard URL** — how you reach the dashboard, e.g. `http://100.86.63.107:5173`
     (or `http://localhost:5173` locally).
   - **Capture token** — the same value as `CAPTURE_TOKEN`.
   - Tick **Capture enabled**, then **Save & test**. It should say
     *"Connected — capturing N target host(s)."*

## Use

Browse a target while capture is on. Requests to hosts in your tracked domains
show up on the dashboard's **Traffic** page within a few seconds. Toggle capture
off in the popup whenever you're not testing.

## Notes / limits

- The list of target hosts mirrors your tracked domains and refreshes every ~60s.
- Capture is best-effort: Chrome may briefly suspend the extension's background
  worker between requests, so an occasional request right after idle can be
  missed. Steady browsing keeps it active.
- Chrome/Chromium only for now (uses the MV3 `webRequest` observer API).
