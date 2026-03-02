# Agentic VAPT

An AI-powered web penetration testing system. Submit a target URL and the system autonomously crawls it, generates attack hypotheses, awaits human approval, then runs exploit agents to confirm each vulnerability — producing a full HTML/PDF report.

> **For authorized security testing only.** Only scan systems you own or have explicit written permission to test.

---

## How It Works

The pipeline runs through 6 phases:

| Phase | What happens |
|-------|-------------|
| **CRAWLING** | Playwright BFS crawler extracts URLs, forms, cookies, headers, and JS endpoints |
| **SCANNING** | Passive header audit — checks for missing CSP, HSTS, X-Frame-Options, etc. |
| **RECON** | GPT-4o reads the surface notes and outputs 8–15 attack hypotheses |
| **AWAITING_APPROVAL** | Human gate — review the hypothesis list and authorize before anything is sent |
| **EXPLOITING** | One GPT-4o ReAct agent per hypothesis (max 15 turns, up to 3 concurrent browsers) |
| **DONE** | Report compiled with screenshots, available as HTML and PDF download |

### Vulnerability Coverage

XSS · SQLi (form + JSON body) · SSTI · Command Injection · Path Traversal / LFI · SSRF (AWS/GCP/private IPs) · Open Redirect · CORS · Exposed Files · API Doc Exposure · Default Credentials · IDOR / Auth Bypass · Security Header Misconfiguration

---

## Stack

- **Backend** — Python 3.12, FastAPI, Playwright (headless Chromium), OpenAI GPT-4o, httpx
- **Frontend** — Next.js 16, React 19, TypeScript, SSE for live phase updates
- **Reports** — Jinja2 HTML + WeasyPrint PDF

---

## Prerequisites

- Python 3.12+
- Node.js 18+
- Docker (for the demo target)
- An OpenAI API key

---

## Setup

### 1. Clone the repo

```bash
git clone <repo-url>
cd Agentic-VAPT
```

### 2. Backend

```bash
cd backend

# Create and activate a virtual environment
python3 -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate

# Install Python dependencies
pip install -r requirements.txt

# Install Playwright browsers
playwright install chromium
```

Create `backend/.env`:

```env
OPENAI_API_KEY=sk-...
```

### 3. Frontend

```bash
cd frontend
npm install
```

---

## Running

### Start a demo target (DVWA)

```bash
docker run -d -p 80:80 vulnerables/web-dvwa
```

### Start the backend

```bash
cd backend
source venv/bin/activate && pip install -r requirements.txt && python3 -m uvicorn main:app --reload --port 8000
# Runs on http://localhost:8000
```

### Start the frontend

```bash
cd frontend
npm run dev
# Runs on http://localhost:3000
```

### Run a scan

1. Open [http://localhost:3000](http://localhost:3000)
2. Enter a target URL (e.g. `http://localhost:80`)
3. Wait for crawl + recon to complete
4. Review the generated hypotheses and check the authorization checkbox
5. Watch exploit agents run in real time
6. Download the HTML or PDF report when done

---

## Project Structure

```
backend/
  main.py                       FastAPI app entry point
  models.py                     Pydantic models (ScanState, Hypothesis, AgentResult, ExploitStep)
  routers/scan.py               API endpoints + 6-phase pipeline orchestration
  pipeline/
    crawler.py                  Playwright BFS crawler → SurfaceReport
    scanner.py                  Passive header audit + surface notes builder
  agents/
    recon_agent.py              GPT-4o: SurfaceReport → list[Hypothesis]
    exploit_agent.py            GPT-4o ReAct loop: Hypothesis → AgentResult
    orchestrator.py             Runs all exploit agents (asyncio.Semaphore(3))
  tools/browser_tool.py         Playwright helpers: navigate, fill_and_submit, screenshot, fetch_url
  reporters/report_compiler.py  Jinja2 HTML report with embedded base64 screenshots

frontend/src/app/
  page.tsx                      Hero / scan initiation page
  scan/[id]/page.tsx            Live dashboard (SSE: phase, surface, hypotheses, agent_result, done)
  scan/[id]/report/page.tsx     Report viewer + PDF download
```

---

## SSE Events

The frontend subscribes to `GET /scan/{id}/stream` and receives:

| Event | Payload |
|-------|---------|
| `phase` | Current pipeline phase string |
| `surface` | Crawled surface data |
| `hypotheses` | List of generated hypotheses |
| `agent_result` | Result from a completed exploit agent |
| `done` | Final signal, report ready |
| `error` | Error message |

---

## Notes

- Scans are held **in memory only** — restarting the backend clears all scan state.
- Screenshots are saved to `backend/screenshots/{scan_id}/step_NN_label.png`.
- The exploit agent uses `tool_choice="required"` — GPT-4o must call a tool every turn.
- Screenshots are captured automatically on every `navigate`, `fill_field`, and `click` action.
