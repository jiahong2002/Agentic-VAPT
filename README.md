<div align="center">

```
  ⌖  A G E N T V A P T
```

**AI-Powered Vulnerability Assessment & Penetration Testing**

[![Python](https://img.shields.io/badge/Python-3.12-3776AB?style=flat-square&logo=python&logoColor=white)](https://python.org)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.110-009688?style=flat-square&logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com)
[![Next.js](https://img.shields.io/badge/Next.js-14-000000?style=flat-square&logo=next.js&logoColor=white)](https://nextjs.org)
[![OpenAI](https://img.shields.io/badge/OpenAI-GPT--5-412991?style=flat-square&logo=openai&logoColor=white)](https://openai.com)
[![Supabase](https://img.shields.io/badge/Supabase-Auth%20%2B%20DB-3ECF8E?style=flat-square&logo=supabase&logoColor=white)](https://supabase.com)
[![Playwright](https://img.shields.io/badge/Playwright-Chromium-2EAD33?style=flat-square&logo=playwright&logoColor=white)](https://playwright.dev)

*Submit a URL. Approve the plan. Read your report.*

</div>

---

## What is AgentVAPT?

AgentVAPT is a full-stack agentic penetration testing platform. You give it a target URL — it crawls the application, generates a set of attack hypotheses using GPT-5, and then dispatches one autonomous AI agent per hypothesis. Each agent runs an independent ReAct loop: it forms a precise attack plan, executes it using a real browser, observes the result, revises if needed, and either confirms or rules out the vulnerability.

The entire process is streamed live to a dashboard. You stay in control — a human approval gate sits between recon and exploitation, letting you review every planned attack before any payload fires.

No scripts. No static rules. Just agents that think.

---

## Pipeline

```
  ┌─────────────────────────────────────────────────────────────────────────┐
  │                          AgentVAPT Pipeline                             │
  └─────────────────────────────────────────────────────────────────────────┘

  [ Target URL ]
        │
        ▼
  ┌─────────────┐    Playwright BFS crawler — discovers URLs, forms,
  │  1. CRAWL   │    cookies, headers, JS endpoints, tech stack
  └─────────────┘
        │
        ▼
  ┌─────────────┐    Nuclei active scanner + passive header audit
  │  2. SCAN    │    (CSP, HSTS, X-Frame-Options, etc.)
  └─────────────┘
        │
        ├──────────────────────────────────────────────┐
        │                                              │ (if SAST enabled)
        ▼                                              ▼
  ┌─────────────┐                            ┌──────────────────┐
  │  3. RECON   │    GPT-5 reads surface      │  SAST ANALYSIS   │
  │    AGENT    │    notes → 8–15 attack      │  semgrep + npm   │
  └─────────────┘    hypotheses               │  audit on repo   │
        │                                    └──────────────────┘
        ▼
  ┌─────────────┐    ⚠  Human reviews every planned attack.
  │  4. APPROVE │    Must check a box to authorize exploitation.
  └─────────────┘
        │
        ▼
  ┌─────────────────────────────────────────────────────────────┐
  │  5. EXPLOIT                                                  │
  │                                                             │
  │   Hypothesis A ──► Agent A (ReAct loop, max 300 turns)      │
  │   Hypothesis B ──► Agent B        ┐                         │
  │   Hypothesis C ──► Agent C        ├── 3 concurrent browsers │
  │        ...             ...        ┘                         │
  │                                                             │
  │   Each agent: navigate → inspect → inject → observe → revise│
  └─────────────────────────────────────────────────────────────┘
        │
        ▼
  ┌─────────────┐    HTML report + PDF download
  │  6. REPORT  │    with screenshots, CVSS scores, remediation
  └─────────────┘
```

---

## Features

### Autonomous Exploit Agents
Each agent gets a single vulnerability class to investigate. It uses a **tool-calling ReAct loop** (up to 300 turns) with a live headless Chromium browser. Every navigation, form fill, and click is automatically screenshotted and recorded as evidence.

The loop only ends when the agent calls `submit_verdict` — either with confirmed exploitation proof, or after exhausting all attack surfaces.

### Human-in-the-Loop Gate
Before any exploit payload fires, the platform presents the full hypothesis list for review. You must explicitly authorize the agents to proceed. Nothing runs without your sign-off.

### Live Dashboard
Real-time updates via **Server-Sent Events**. Watch agents spin up, see confirmed vulnerabilities surface in real time, track the exploit progress bar. Navigate away — the scan keeps running in the background. Come back at any time via Scan History to resume the live view.

### Optional SAST
Toggle on static analysis when starting a scan. Provide a GitHub repo URL and Personal Access Token — the platform clones the repo and runs `semgrep` + `npm audit`, surfacing code-level findings alongside the DAST results.

### Reports
Every completed scan generates a full HTML report with:
- Executive summary and risk score breakdown
- Per-finding sections with reproduction steps
- Embedded screenshots at every exploitation step
- Remediation guidance
- CVSS v3 scores on confirmed findings

Downloadable as a styled PDF directly from the report viewer.

---

## Technique Coverage

| Category | Techniques |
|---|---|
| **Injection** | SQL Injection, Reflected XSS, Stored XSS, Server-Side Template Injection, Command Injection, Path Traversal / LFI, XXE |
| **Access Control** | IDOR, Broken Access Control, Default Credentials |
| **Server-Side** | SSRF (AWS/GCP metadata, private IPs), Open Redirect, CORS Misconfiguration |
| **Information Disclosure** | Exposed Sensitive Files, API Documentation Exposure, Security Header Misconfiguration |
| **Other** | File Upload Vulnerabilities, Prototype Pollution, CSRF |

---

## Stack

| Layer | Technology |
|---|---|
| **Backend** | Python 3.12, FastAPI, `asyncio` |
| **AI** | OpenAI GPT-5 (`gpt-5`) — recon agent + all exploit agents |
| **Browser** | Playwright (headless Chromium) — crawling + exploitation |
| **Active Scanner** | Nuclei — active CVE/misconfiguration detection |
| **Frontend** | Next.js 14, TypeScript, CSS Modules |
| **Realtime** | Server-Sent Events (`sse-starlette`) |
| **Auth + DB** | Supabase (RS256 JWT, PostgreSQL, Storage) |
| **Reports** | Jinja2 HTML → Playwright PDF render |

---

## Project Structure

```
.
├── backend/
│   ├── main.py                    # FastAPI app, CORS config
│   ├── models.py                  # Pydantic models (ScanState, Hypothesis, AgentResult…)
│   ├── auth.py                    # JWKS-based JWT verification (RS256)
│   ├── supabase_client.py         # Singleton async Supabase client
│   ├── routers/
│   │   ├── scan.py                # All API endpoints + 6-phase pipeline orchestration
│   │   └── auth.py                # Login / signup / me endpoints
│   ├── pipeline/
│   │   ├── crawler.py             # Playwright BFS crawler → SurfaceReport
│   │   ├── scanner.py             # Header audit + surface notes builder
│   │   └── vuln_scanner.py        # Nuclei integration
│   ├── agents/
│   │   ├── recon_agent.py         # GPT-5: SurfaceReport → list[Hypothesis]
│   │   ├── exploit_agent.py       # GPT-5 ReAct loop: Hypothesis → AgentResult
│   │   └── orchestrator.py        # asyncio.Semaphore(3) — runs all exploit agents
│   ├── tools/
│   │   └── browser_tool.py        # Playwright helpers used by exploit agents
│   └── reporters/
│       └── report_compiler.py     # Jinja2 HTML report with embedded screenshots
│
├── frontend/src/
│   ├── middleware.ts               # Route protection
│   └── app/
│       ├── page.tsx                # Landing page
│       ├── dashboard/
│       │   ├── page.tsx            # Scan initiation (DAST + optional SAST toggle)
│       │   ├── layout.tsx          # Navbar layout for all dashboard routes
│       │   └── scans/
│       │       └── page.tsx        # Scan history table
│       ├── scan/[id]/
│       │   ├── page.tsx            # Live scan dashboard (SSE)
│       │   └── report/
│       │       └── page.tsx        # Report viewer + PDF download
│       └── lib/
│           └── auth.ts             # apiFetch wrapper, token management
├── docker-compose.yml
├── README.md
└── setup.sql
```

---

## Setup

### Prerequisites
- Docker & Docker Compose
- A [Supabase](https://supabase.com) project

### 1. Database

Run `setup.sql` in your Supabase SQL editor to create the required tables and storage buckets.

### 2. Configure Environment

```bash
cp backend/.env.example backend/.env
# Fill in: OPENAI_API_KEY, SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY
```

### 3. Run

```bash
docker compose up --build
```

Both services start automatically — backend on `:8000`, frontend on `:3000`.

Visit `http://localhost:3000`

### Test Target (DVWA)

```bash
docker run -d -p 80:80 vulnerables/web-dvwa
```

Then scan `http://localhost:80` — DVWA is intentionally vulnerable and great for verifying agent accuracy.

---

## Environment Variables

**`backend/.env`**

| Variable | Description |
|---|---|
| `OPENAI_API_KEY` | OpenAI API key (GPT-5 access required) |
| `SUPABASE_URL` | Your Supabase project URL |
| `SUPABASE_SERVICE_ROLE_KEY` | Service role key (bypasses RLS for backend operations) |
| `CORS_ORIGINS` | *(Optional)* Comma-separated allowed origins. Default: `http://localhost:3000` |

---

## API Reference

| Method | Endpoint | Auth | Description |
|---|---|---|---|
| `POST` | `/api/scan/start` | ✓ | Start a new scan |
| `GET` | `/api/scan/{id}/events` | token | SSE stream of live scan events |
| `GET` | `/api/scan/{id}/state` | ✓ | Full state snapshot (UI rehydration) |
| `POST` | `/api/scan/{id}/approve` | ✓ | Authorize exploit phase |
| `POST` | `/api/scan/{id}/cancel` | ✓ | Cancel scan |
| `GET` | `/api/scan/{id}/report` | ✓ | HTML report |
| `GET` | `/api/scan/{id}/report/pdf` | ✓ | PDF report download |
| `GET` | `/api/scans` | ✓ | List user's scan history |
| `POST` | `/api/auth/signup` | — | Create account |
| `POST` | `/api/auth/login` | — | Login |
| `GET` | `/api/auth/me` | ✓ | Current user info |

### SSE Events

| Event | Payload | Description |
|---|---|---|
| `phase` | `{ phase, message }` | Pipeline phase transition |
| `surface` | `{ urls_found, forms_found, tech_stack, … }` | Crawl results |
| `hypotheses` | `{ count, hypotheses[] }` | Recon agent output |
| `sast_findings` | `{ findings[] }` | Static analysis results |
| `agent_result` | `{ hypothesis_id, status, severity, … }` | Single agent verdict |
| `done` | `{ total, confirmed, unconfirmed }` | Scan complete |
| `error` | `{ message }` | Fatal error |

---

## How the Exploit Agent Works

Each agent runs a **ReAct (Reason + Act) loop** driven by GPT-5 with `tool_choice="required"` — the model *must* call a tool every turn, preventing it from talking itself out of testing.

```
┌─────────────────────────────────────────────────────────┐
│                   Exploit Agent Loop                    │
│                                                         │
│  Assignment received (technique + attack surface)       │
│           │                                             │
│           ▼                                             │
│  ┌─── HYPOTHESIZE ───────────────────────────────────┐  │
│  │  Form specific attack hypothesis                  │  │
│  │  (which URL, which param, which payload variant)  │  │
│  └───────────────────────────────────────────────────┘  │
│           │                                             │
│           ▼                                             │
│  ┌─── EXECUTE ───────────────────────────────────────┐  │
│  │  navigate / fill_field / click / fetch_url        │  │
│  │  → auto-screenshot on every action                │  │
│  └───────────────────────────────────────────────────┘  │
│           │                                             │
│           ▼                                             │
│  ┌─── ANALYZE & REVISE ──────────────────────────────┐  │
│  │  Did the attack work?                             │  │
│  │  YES → submit_verdict(verified=true) ────────────────► CONFIRMED
│  │  NO  → why? try next surface / payload variant    │  │
│  └───────────────────────────────────────────────────┘  │
│           │                                             │
│           └──────── repeat up to 300 turns ─────────────┘
│                                                         │
│  All surfaces exhausted → submit_verdict(verified=false) ► UNCONFIRMED
└─────────────────────────────────────────────────────────┘
```

**Tools available to each agent:**
`navigate` · `get_page_content` · `fill_field` · `select_option` · `click` · `execute_js` · `get_cookies` · `upload_file` · `fetch_url` · `take_screenshot` · `submit_verdict`

**Strict gate:** an agent may only call `submit_verdict(verified=false)` after visiting every candidate URL, trying at least 5 distinct payloads per promising injection point, attempting at least 3 attack surfaces, and making at least 15 total tool calls. Premature surrender is forbidden.

---

## Security Notice

AgentVAPT is built for **authorized security testing only**. Only scan systems you own or have explicit written permission to test. The platform includes a mandatory authorization checkbox before exploitation begins — this is not a formality.

---

<div align="center">

Built at DL Week 2026

</div>
