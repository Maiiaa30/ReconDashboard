<div align="center">

# 🛰️ Recon Dashboard

### A single-operator, self-hosted red team attack-surface & recon platform

*Passive-first reconnaissance, exposure monitoring, OSINT aggregation and gated active scanning — all from the browser, no terminal required.*

<br>

[![License: CC BY-NC-SA 4.0](https://img.shields.io/badge/License-CC%20BY--NC--SA%204.0-lightgrey.svg?style=for-the-badge)](./LICENSE)
[![CI](https://img.shields.io/github/actions/workflow/status/Maiiaa30/ReconDashboard/ci.yml?style=for-the-badge&label=CI)](https://github.com/Maiiaa30/ReconDashboard/actions/workflows/ci.yml)
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

- 🔎 **Passive-first recon** — certificate transparency, DNS, WHOIS, tech fingerprinting, archived-URL sources, cloud-bucket enumeration and "Shodan-of-each-domain" exposure (ASN, TLS-cert SANs, CVEs), all keyless where possible.
- 🚨 **Continuous monitoring** — per-domain auto-recon on a schedule, subdomain diffing, a new-CVE-on-known-asset watch, and instant **Discord alerts** the moment a new subdomain appears.
- 🎯 **Gated active scanning** — `nmap`, `nuclei`, `ffuf`, `sqlmap` and friends, locked behind `active_authorized`, an engagement scope (allow/deny) and an authorization window — never fired at an unauthorized target.
- 🧠 **Intelligence & triage** — deterministic rules-based scoring, **attack-path correlation** rendered as a network graph, an optional AI advisor, and **immutable engagement report snapshots**.
- 🕵️ **People & LLM security** — passive people/account **OSINT** pivots, domain **breach-exposure** lookups, and an **OWASP-Top-10-for-LLMs** red-team testing reference.
- ⌨️ **Operator-first UX** — grouped navigation, a **Ctrl-K command palette**, **toast + desktop notifications when a scan/tool finishes**, a mobile-friendly drawer, Markdown notes (push to Discord) and an auto-saved Excalidraw canvas.
- 🔐 **Built to be private** — single hardened login with optional TOTP 2FA, meant to live behind Tailscale, encrypted database backups you control, and CI-tested security rails.

---

## 🧩 Modules

The sidebar is grouped into **Overview · Recon · OSINT & Leaks · Offensive · Workspace · System**.

| Module | What it does | Mode |
| --- | --- | :---: |
| **Home** | Engagement dashboard — KPI vitals, attention buckets (never-scanned / new subs / high-risk), top open findings, recent-CVE changes | — |
| **Domains** | Track targets; per-domain `passive_only` / `active_authorized` mode; engagement scope (allow/deny hosts + CIDRs) + authorization window; scheduled auto-monitoring | — |
| **Intel** | Rules-based triage + **attack-path correlation** as a force-directed **network graph**; optional **AI advisor** (prioritized, gated testing plan) | — |
| **Methodology** | Recon-skills coverage per target — which methodologies apply, per-step found / done / todo, one-click run, manual overrides | — |
| **Subdomains** | Passive discovery (crt.sh · certspotter · subfinder), HTTP-probe enrichment, **sortable by status / host / IP / last-seen**, diff & flag new, Discord alerts, exports | 🟢 passive |
| **Screenshots** | Headless-Chromium gallery with lightbox | 🟢 passive |
| **Exposure** | "Shodan of each domain" via InternetDB + cvedb — ports, CVEs, CPEs — plus **ASN / reverse-IP** and **TLS-cert SAN** harvest; interesting ports flagged | 🟢 passive |
| **Ports** | Every open port across the target (from Exposure + nmap), de-duped and filterable, with **port intelligence** — cameras/DVR, ICS & building-automation, databases, remote-access and admin panels auto-flagged by risk | 🟢 passive |
| **OSINT** | DNS · WHOIS · cert transparency · zone-transfer · tech fingerprint · archived URLs (Wayback / CommonCrawl / urlscan / OTX) · **cloud-bucket enum** | 🟢 passive |
| **Social Forensics** | Passive people/account **OSINT** — pivot a username / email / name / phone into public-profile, search-dork and breach-lookup links, plus a people-OSINT methodology | 🟢 passive |
| **Data Leaks** | Domain **breach exposure** — configurable provider (HIBP / DeHashed / LeakCheck) *plus* a free, keyless per-email breach check and a HIBP domain link | 🟢 passive |
| **WHOIS / Check Host** | Ad-hoc lookups — WHOIS (domain + IP) and reachability (ping / TCP / DNS / HTTP), rate-limited | 🟢 passive |
| **WAF / Origin** | Origin-IP discovery behind Cloudflare / WAF | 🟢 passive |
| **Scans** | `nmap` · `nuclei` (template-tag presets) · `ffuf` — **gated, loud** | 🔴 active |
| **Tools** | `katana` · `naabu` · `dalfox` · `sslscan` · `sqlmap` · WordPress enum · 403/401 bypass · HTTP-method audit · exposed-datastore probes — **gated** | 🔴 active |
| **OWASP** | In-process HTTP checks (headers, exposed `.env`/`.git`, reflected XSS, open redirect, CORS, TRACE, listings) + JS endpoint/secret extraction + nuclei pass, target-aware | 🔴 active |
| **Fuzzing** | `ffuf` content discovery with target + wordlist pickers | 🔴 active |
| **LLM Security** | Reference — **OWASP Top 10 for LLMs**, a searchable red-team **payload library**, and per-model testing methodology (Gemini / Llama / GPT / Claude / …) | 📖 reference |
| **Findings** | Scored & deduped with "why this score" + CVE detail, triage lifecycle, bulk triage, CSV/JSON + Markdown/HTML reports, **immutable report snapshots** | — |
| **Notes / Canvas** | Markdown notes (push to Discord) · Excalidraw board auto-saved to the DB | — |
| **Logs / Audit / Settings** | Live activity log with job control · append-only **audit ledger** · 2FA enrollment · system status · encrypted backup & restore | — |

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
- **Database** — SQLite via Drizzle ORM (`better-sqlite3`), versioned migrations applied on boot
- **Jobs** — a `jobs` table polled by an in-process worker with **two concurrent lanes** (passive + loud), so a long loud scan never blocks passive monitoring while loud scans still run one-at-a-time per target — **no Redis**
- **Quality** — **GitHub Actions CI** on every push: typecheck + unit tests (backend) and typecheck + build (frontend)
- **Packaging** — Docker + Docker Compose

---

## 🚀 Quick start

```bash
git clone https://github.com/Maiiaa30/ReconDashboard.git
cd ReconDashboard
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
- 🛡️ Outbound HTTP checks refuse targets resolving to internal/private/loopback IPs (**SSRF defense**), and follow redirects with a re-resolve on every hop.
- 🧪 The security rails — auth default-deny, active-scan gating, the SSRF guard and finding dedup — are covered by **unit tests run in CI on every push** (`cd backend && npm test`).
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
