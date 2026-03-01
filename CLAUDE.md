# PenTest Agent — Claude Code Context

## What this project is
AI-powered web penetration testing system. User submits a target URL → system crawls it → Recon Agent generates attack hypotheses → human approves → Exploit Agents confirm each vulnerability → HTML/PDF report.

## Stack
- **Backend**: Python 3.12, FastAPI, Playwright (headless Chromium), OpenAI GPT-4o, httpx
- **Frontend**: Next.js 14, TypeScript, SSE for live updates
- **Report**: Jinja2 HTML + WeasyPrint PDF

## Key files
```
backend/
  main.py                     FastAPI app entry point
  models.py                   Pydantic models (ScanState, Hypothesis, AgentResult, ExploitStep)
  routers/scan.py             All API endpoints + 6-phase pipeline orchestration
  pipeline/
    crawler.py                Playwright BFS crawler → SurfaceReport
    scanner.py                Header audit + build_surface_notes() for recon prompt
  agents/
    recon_agent.py            GPT-4o: SurfaceReport → list[Hypothesis]
    exploit_agent.py          GPT-4o ReAct loop: Hypothesis → AgentResult (TRUE agentic, function-calling)
    orchestrator.py           Runs all exploit agents with asyncio.Semaphore(3) for concurrency
  tools/browser_tool.py       Playwright helpers: navigate, fill_and_submit, take_screenshot, fetch_url
  reporters/report_compiler.py Jinja2 HTML report with embedded base64 screenshots
frontend/src/app/
  page.tsx                    Hero / scan initiation
  scan/[id]/page.tsx          Live dashboard (SSE: phase, surface, hypotheses, agent_result, done)
  scan/[id]/report/page.tsx   Report viewer + PDF download
```

## Architecture — pipeline phases
1. **CRAWLING** — Playwright BFS, extracts URLs / forms / cookies / headers / JS endpoints
2. **SCANNING** — Passive header audit (missing CSP, HSTS, X-Frame-Options etc.)
3. **RECON** — GPT-4o reads surface notes, outputs 8–15 `Hypothesis` objects
4. **AWAITING_APPROVAL** — Human gate: shows hypothesis list, user must check a box and authorize
5. **EXPLOITING** — One GPT-4o agent per hypothesis, true ReAct loop (max 15 turns), tools: navigate/get_page_content/fill_field/click/fetch_url/take_screenshot/submit_verdict
6. **DONE** — Report compiled, available as HTML and PDF

## Exploit agent design (ReAct loop)
- `tool_choice="required"` — GPT-4o MUST call a tool every turn
- Auto-screenshots on every `navigate`, `fill_field`, `click` — no gaps in visual evidence
- `submit_verdict` tool ends the loop, produces structured steps for the report
- Concurrency: max 3 browsers at once (semaphore in orchestrator.py)
- Message history: explicit dict format (not model_dump) for reliability

## Technique coverage
XSS, SQLi (form + JSON body), SSTI, Command Injection, Path Traversal/LFI, SSRF (AWS/GCP/private IPs), Open Redirect, CORS, Exposed Files, API Doc Exposure, Default Credentials, IDOR/Auth Bypass, Security Header Misconfig

## Running locally
```bash
# Demo target (DVWA)
docker run -d -p 80:80 vulnerables/web-dvwa

# Backend
cd backend && uvicorn main:app --reload

# Frontend
cd frontend && npm run dev
```
Then visit http://localhost:3000, submit http://localhost:80

## Environment
`backend/.env` must contain:
```
OPENAI_API_KEY=sk-...
```

## Important conventions
- Never use `client = AsyncOpenAI()` at module level — use the lazy `_get_client()` singleton
- Screenshots save to `backend/screenshots/{scan_id}/step_NN_label.png`
- The `ScanState` is in-memory only (no database) — scans are lost on server restart
- SSE events: `phase`, `surface`, `hypotheses`, `agent_result`, `done`, `error`
