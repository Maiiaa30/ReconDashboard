<div align="center">

# 🛰️ Recon Dashboard

### A single-operator, self-hosted red team attack-surface & recon platform

*Passive-first reconnaissance, exposure monitoring, OSINT aggregation and gated active scanning — all from the browser, no terminal required.*

<br>

[![License: CC BY-NC-SA 4.0](https://img.shields.io/badge/License-CC%20BY--NC--SA%204.0-lightgrey.svg?style=for-the-badge)](./LICENSE)
[![Status](https://img.shields.io/badge/status-actively%20developed-brightgreen?style=for-the-badge)](#)
[![Authorized use only](https://img.shields.io/badge/use-authorized%20targets%20only-red?style=for-the-badge)](#-legal--ethical-use)

<br>

![TypeScript](https://img.shields.io/badge/TypeScript-3178C6?style=flat-square&logo=typescript&logoColor=white)
![React](https://img.shields.io/badge/React-20232A?style=flat-square&logo=react&logoColor=61DAFB)
![Vite](https://img.shields.io/badge/Vite-646CFF?style=flat-square&logo=vite&logoColor=white)
![Tailwind CSS](https://img.shields.io/badge/Tailwind-38B2AC?style=flat-square&logo=tailwind-css&logoColor=white)
![Node.js](https://img.shields.io/badge/Node.js-339933?style=flat-square&logo=node.js&logoColor=white)
![Fastify](https://img.shields.io/badge/Fastify-000000?style=flat-square&logo=fastify&logoColor=white)
![SQLite](https://img.shields.io/badge/SQLite-07405E?style=flat-square&logo=sqlite&logoColor=white)
![Docker](https://img.shields.io/badge/Docker-2496ED?style=flat-square&logo=docker&logoColor=white)

</div>

---

> [!WARNING]
> ## ⚖️ Legal & Ethical Use
> This is **offensive security tooling**. Run it **only** against systems you own or are **explicitly authorized in writing** to test. Unauthorized scanning, fuzzing or exploitation is illegal in most jurisdictions. Active/loud modules are gated behind an explicit per-domain `active_authorized` flag *by design* — that gate is a safeguard, not a suggestion. **You alone are responsible for how you use this software.** See the [disclaimer](#-disclaimer).

---

## ✨ Overview

**Recon Dashboard** is a personal, single-user platform for tracking assets and reconnaissance data across authorized engagements. It leans **passive-first** — pulling everything it safely can without touching the target — and keeps the loud, active tooling behind explicit authorization gates. Everything runs **server-side as background jobs** and is driven entirely from a dark, modern web UI. No terminal, no copy-pasting tool output.

- 🔎 **Passive-first recon** — certificate transparency, DNS, WHOIS, tech fingerprinting, archived-URL sources and "Shodan-of-each-domain" exposure data, all keyless where possible.
- 🚨 **Continuous monitoring** — per-domain auto-recon on a schedule, subdomain diffing, and instant **Discord alerts** the moment a new subdomain appears.
- 🎯 **Gated active scanning** — `nmap`, `nuclei`, `ffuf` and friends, locked behind `active_authorized` and never fired at an unauthorized target.
- 🧠 **Finding triage** — deterministic rules-based scoring, a full open→resolved lifecycle, and exportable per-domain Markdown reports.
- 🗒️ **Operator workspace** — Markdown notes (one-click push to Discord) and an embedded Excalidraw canvas, auto-saved.
- 🔐 **Built to be private** — single hardened login with optional TOTP 2FA, meant to live behind Tailscale, with encrypted database backups you control.

---

## 🧩 Modules

| Module | What it does | Mode |
| --- | --- | :---: |
| **Domains** | Track targets; per-domain `passive_only` / `active_authorized` mode; scheduled auto-monitoring; KPI overview | — |
| **Subdomains** | Passive discovery (crt.sh · certspotter · subfinder), HTTP-probe enrichment, diff & flag new, Discord alerts, exports | 🟢 passive |
| **Exposure** | "Shodan of each domain" via Shodan InternetDB + cvedb — open ports, CVEs, CPEs (free, no key) | 🟢 passive |
| **OSINT** | DNS · WHOIS · cert transparency · zone-transfer · server/tech fingerprint · archived URLs (Wayback, Common Crawl, urlscan, OTX) | 🟢 passive |
| **WAF / Origin** | Origin-IP discovery behind Cloudflare / WAF | 🟢 passive |
| **Screenshots** | Headless-Chromium gallery with lightbox | 🟢 passive |
| **Scans** | `nmap` · `nuclei` (template-tag presets) · `ffuf` — **gated, loud** | 🔴 active |
| **Tools** | `katana` · `naabu` · `dalfox` · `sslscan` · WordPress enum — **gated** | 🔴 active |
| **OWASP** | In-process HTTP checks (headers, exposed `.env`/`.git`, reflected XSS, open redirect, CORS, TRACE, listings) + nuclei pass, target-aware | 🔴 active |
| **Fuzzing** | `ffuf` content discovery with target + wordlist pickers | 🔴 active |
| **Findings** | Scored & deduped with "why this score" + CVE detail, triage lifecycle, CSV/JSON export, per-domain Markdown report | — |
| **Notes / Canvas** | Markdown notes (push to Discord) · Excalidraw board auto-saved to the DB | — |
| **Logs / Settings** | Live activity log with job control · 2FA enrollment · system status · encrypted backup | — |

---

## 🏗️ Architecture

```
┌────────────────────────┐        ┌──────────────────────────────┐
│  React + Vite SPA       │  REST  │  Fastify + TypeScript API     │
│  (Tailwind, dark UI)    │ ─────► │  ├─ auth (argon2 + TOTP)      │
└────────────────────────┘        │  ├─ jobs table + worker loop  │
                                   │  └─ recon CLI tools (execFile)│
                                   └──────────────┬───────────────┘
                                                  │
                                          ┌───────▼────────┐
                                          │  SQLite (Drizzle)│
                                          └──────────────────┘
```

- **Frontend** — React + Vite + TypeScript + Tailwind (single SPA, PWA-friendly)
- **Backend** — Node.js + Fastify + TypeScript (REST API)
- **Database** — SQLite via Drizzle ORM (`better-sqlite3`)
- **Jobs** — a `jobs` table polled by an in-process worker — **no Redis**
- **Packaging** — Docker + Docker Compose

---

## 🚀 Quick start

```bash
git clone https://github.com/Maiiaa30/RedTeamDashboard.git
cd RedTeamDashboard
cp .env.example .env        # then edit it — never commit .env
docker compose up --build
```

- **Frontend** → <http://localhost:5173>
- **Backend health** → <http://localhost:3001/api/health>

Set a real `ADMIN_PASSWORD` and a 32+ char `SESSION_SECRET` before any real use — the server refuses to boot without them. On first run it seeds the operator account, applies migrations, and logs a one-time `otpauth://` URL so you can enable 2FA later from **Settings**. The SQLite DB lives in the `app-data` volume and survives rebuilds.

> Prefer no Docker? Run `npm install && npm run dev` in both `backend/` and `frontend/` — passive recon and the in-process OWASP/WordPress checks still work even if the CLI tools aren't installed; anything binary-backed degrades gracefully and reports itself as unavailable under **Settings → System status**.

---

## 🔒 Security ground rules

These are enforced in code, not just documented:

- 🖥️ Security tooling is **server-side only** — every action is triggered from the UI; no raw shell input is ever executed.
- 🧵 No shell command strings are built from user input — subprocesses use `execFile` / `spawn` with **explicit argument arrays**.
- ✅ Every domain/host input is validated against a **strict allowlist regex** before use.
- 🚧 Active/loud modules require per-domain `active_authorized` (a passive domain needs an explicit per-run confirmation), and every active target must belong to the authorized domain.
- 🛡️ Outbound HTTP checks refuse targets resolving to internal/private/loopback IPs (**SSRF defense**), with the security-critical validation covered by unit tests (`cd backend && npm test`).
- 🔑 No secrets in code — everything sensitive comes from `.env`.

---

## 🌐 Deployment

Locally you run `docker compose up`. In production this is designed to sit on a private VM (Oracle Always Free / Hetzner / OVH) **behind Tailscale** — never exposed to the public internet. There is no public port mapping beyond what Tailscale reaches, and no public TLS/ACME by design. Keep an **encrypted backup** (Settings → Encrypted backup) off-box so a host suspension is never a data loss.

---

## 📄 License

This project is licensed under **Creative Commons Attribution-NonCommercial-ShareAlike 4.0 International (CC BY-NC-SA 4.0)** — see [`LICENSE`](./LICENSE).

**In plain terms** 🧷:

- ✅ You may use, study, modify and share it freely, with **attribution**.
- 🚫 **NonCommercial** — no commercial use of this project or derivatives.
- 🔁 **ShareAlike** — any distributed derivative must be released under this **same license**.
- ⚠️ It comes with **no warranty** of any kind.

```
Recon Dashboard — a self-hosted red team recon platform
Copyright (C) 2026  Maiiaa30

Licensed under CC BY-NC-SA 4.0 (Attribution-NonCommercial-ShareAlike 4.0
International). You are free to use, modify and share this work — with
attribution, non-commercially, and under the same license — see LICENSE
or https://creativecommons.org/licenses/by-nc-sa/4.0/
```

---

## ⚠️ Disclaimer

This software is provided for **authorized security testing and educational purposes only**. The author accepts **no liability** for any misuse or damage caused by this program. Running reconnaissance, scanning, fuzzing or exploitation tooling against systems without explicit, written authorization from the owner is **illegal** and unethical. By using this software you agree that you are solely responsible for your actions and that you will comply with all applicable laws.

---

<div align="center">

Built with ☕ and a healthy respect for scope.

**[⬆ back to top](#️-recon-dashboard)**

</div>
