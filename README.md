# Agentic VAPT

A human-governed Vulnerability Assessment & Penetration Testing system powered by **OpenAI Codex** and **OWASP ZAP**.

## Architecture

```
Browser (React)
    ↕
FastAPI Backend
    ├── OpenAI Codex  →  Analyzes findings, verifies PT results, generates report narrative
    └── OWASP ZAP     →  Passive scan (VA) + Active scan (PT)
```

## Workflow

```
1. User enters target URL
2. [VA Phase]       ZAP spiders the site → passive scan → Codex analyses alerts
3. [Human Approval] User reviews findings, selects which to escalate to PT
4. [PT Phase]       ZAP active scan on approved targets → Codex verifies findings
5. [Report]         HTML report with executive summary, confirmed vulns, recommendations
```

The **Human Approval** step is mandatory — active scanning never runs without explicit user consent.

---

## Prerequisites

| Tool | Notes |
|------|-------|
| Python 3.11+ | Backend runtime |
| Node.js 18+ | Frontend build |
| OWASP ZAP | [Download](https://www.zaproxy.org/download/) — run in daemon mode |
| Docker | For Juice Shop test target |
| OpenAI API key | Codex-enabled API key |

---

## Setup

### 1. Clone & configure environment

```bash
cp .env.example .env
# Edit .env and fill in OPENAI_API_KEY, OPENAI_MODEL, ZAP_API_KEY
```

### 2. Start test target (OWASP Juice Shop)

```bash
docker compose up -d juice-shop
# Juice Shop available at http://localhost:3000
```

### 3. Start OWASP ZAP in daemon mode

**Windows:**
```cmd
"C:\Program Files\ZAP\zap.bat" -daemon -port 8080 -config api.key=YOUR_ZAP_KEY
```

**macOS/Linux:**
```bash
zap.sh -daemon -port 8080 -config api.key=YOUR_ZAP_KEY
```

### 4. Start the backend

```bash
cd backend
pip install -r requirements.txt
uvicorn main:app --reload --port 8000
```

### 5. Start the frontend

```bash
cd frontend
npm install
npm run dev
# Opens at http://localhost:5173
```

---

## Usage

1. Open [http://localhost:5173](http://localhost:5173)
2. Enter `http://localhost:3000` (Juice Shop)
3. Wait for VA to complete (~2-5 min)
4. Review findings, select which to escalate, click **Approve PT**
5. Wait for PT to complete (~5-10 min)
6. Download the HTML report

---

## Project Structure

```
Agentic-VAPT/
├── backend/
│   ├── main.py              # FastAPI routes
│   ├── ai_agent.py          # OpenAI Codex tool-calling agent
│   ├── zap_client.py        # OWASP ZAP API wrapper
│   ├── report_generator.py  # HTML report (Jinja2)
│   ├── models.py            # Pydantic data models
│   ├── session_store.py     # In-memory session state
│   └── requirements.txt
├── frontend/
│   └── src/
│       ├── App.jsx
│       ├── api.js
│       └── components/
│           ├── URLInput.jsx       # URL entry
│           ├── PhaseTracker.jsx   # Progress indicator
│           ├── VAResults.jsx      # VA findings + approval UI
│           ├── PTResults.jsx      # PT verification results
│           └── ReportViewer.jsx   # Inline report viewer
├── templates/
│   └── report.html.j2       # Report template
├── docker-compose.yml
└── .env.example
```

---

## API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/scan/start` | Start VA scan |
| GET | `/api/scan/{id}/status` | Poll scan state |
| GET | `/api/scan/{id}/va-results` | Get VA findings |
| POST | `/api/scan/{id}/approve-pt` | Approve PT (human checkpoint) |
| POST | `/api/scan/{id}/skip-pt` | Skip PT, generate VA-only report |
| GET | `/api/scan/{id}/pt-results` | Get PT results |
| GET | `/api/scan/{id}/report` | View HTML report |
| GET | `/api/scan/{id}/report/download` | Download HTML report |
| GET | `/api/health` | Health check (ZAP + model status) |
