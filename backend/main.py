import asyncio
import logging
import os
import uuid
from contextlib import asynccontextmanager
from pathlib import Path

from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, FileResponse

load_dotenv()

import ai_agent
import audit_logger
import zap_client
from models import (
    AgentStatus, GreenlightRequest, ReviewFindingRequest,
    ScanState, SDLCPhase,
    StartDesignScan, StartDevScan, StartDeploymentScan,
)
from report_generator import generate_html_report
from session_store import create_session, get_session, update_session, finalize_session, push_progress

logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
logger = logging.getLogger(__name__)

REPORTS_DIR = Path("reports")
REPORTS_DIR.mkdir(exist_ok=True)


@asynccontextmanager
async def lifespan(app: FastAPI):
    if not zap_client.check_zap_connection():
        logger.warning("ZAP not reachable — deployment scans will fail.")
    yield


app = FastAPI(title="Agentic VAPT", version="2.0.0", lifespan=lifespan)
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])


# ── Health ─────────────────────────────────────────────────────────────────

@app.get("/api/health")
async def health():
    return {"status": "ok", "zap_connected": zap_client.check_zap_connection(),
            "model": os.getenv("OPENAI_MODEL", "gpt-4o")}


# ── DESIGN PHASE ───────────────────────────────────────────────────────────

@app.post("/api/design/start")
async def start_design_scan(body: StartDesignScan, background_tasks: BackgroundTasks):
    session = create_session(SDLCPhase.DESIGN, initiated_by=body.initiated_by)
    session.state = ScanState.RUNNING
    update_session(session)
    audit_logger.log(session.session_id, "scan_started", body.initiated_by,
                     f"Design threat model started for '{body.app_name}'")

    async def _run():
        sid = session.session_id
        s = get_session(sid)
        try:
            loop = asyncio.get_event_loop()
            push_progress(sid, "🏗 Analysing application architecture and components…")
            push_progress(sid, "🔍 Mapping attack surface across all STRIDE categories…")
            tm = await loop.run_in_executor(
                None, ai_agent.generate_threat_model, body.app_name, body.app_description)
            push_progress(sid, f"✅ Threat model complete — {len(tm.threats)} STRIDE threats identified")
            s = get_session(sid)
            s.threat_model = tm
            s.state = ScanState.AWAITING_GREENLIGHT
            update_session(s)
            audit_logger.log(sid, "threat_model_complete", "system",
                             f"Generated {len(tm.threats)} STRIDE threats")
        except Exception as exc:
            s = get_session(sid)
            s.state = ScanState.ERROR
            s.error_message = str(exc)
            update_session(s)

    background_tasks.add_task(_run)
    return {"session_id": session.session_id, "state": session.state}


# ── DEVELOPMENT PHASE ──────────────────────────────────────────────────────

@app.post("/api/development/start")
async def start_dev_scan(body: StartDevScan, background_tasks: BackgroundTasks):
    session = create_session(SDLCPhase.DEVELOPMENT, initiated_by=body.initiated_by)
    session.state = ScanState.RUNNING
    session.code_snippet = body.code_snippet
    update_session(session)
    audit_logger.log(session.session_id, "scan_started", body.initiated_by, "SAST analysis started")

    async def _run():
        sid = session.session_id
        s = get_session(sid)
        try:
            loop = asyncio.get_event_loop()
            push_progress(sid, "⌨ Codex agent loading code for static analysis…")
            push_progress(sid, "🔍 Scanning for injection flaws, broken auth, hardcoded secrets…")
            push_progress(sid, "🔒 Checking crypto, SSRF, path traversal, IDOR patterns…")
            findings = await loop.run_in_executor(
                None, ai_agent.analyze_code_sast, body.code_snippet, body.file_context or "")
            push_progress(sid, f"📋 Mapping findings to CWE database…")
            push_progress(sid, f"✅ SAST analysis complete — {len(findings)} security issues found")
            s = get_session(sid)
            s.sast_findings = findings
            s.state = ScanState.AWAITING_GREENLIGHT
            update_session(s)
            audit_logger.log(sid, "sast_complete", "system",
                             f"Found {len(findings)} SAST findings")
        except Exception as exc:
            s = get_session(sid)
            s.state = ScanState.ERROR
            s.error_message = str(exc)
            update_session(s)

    background_tasks.add_task(_run)
    return {"session_id": session.session_id, "state": session.state}


# ── DEPLOYMENT PHASE ───────────────────────────────────────────────────────

@app.post("/api/deployment/start")
async def start_deployment_scan(body: StartDeploymentScan, background_tasks: BackgroundTasks):
    url = body.url.strip()
    if not url.startswith(("http://", "https://")):
        raise HTTPException(status_code=400, detail="URL must start with http:// or https://")
    session = create_session(SDLCPhase.DEPLOYMENT, initiated_by=body.initiated_by)
    session.target_url = url
    session.state = ScanState.RUNNING
    update_session(session)
    audit_logger.log(session.session_id, "scan_started", body.initiated_by,
                     f"DAST scan started on {url}")
    background_tasks.add_task(_run_va_phase, session.session_id)
    return {"session_id": session.session_id, "state": session.state}


async def _run_va_phase(session_id: str) -> None:
    session = get_session(session_id)
    if not session:
        return
    try:
        loop = asyncio.get_event_loop()
        push_progress(session_id, f"🕷 Starting ZAP spider crawl on {session.target_url}…")

        def _spider_progress(pct: int):
            s = get_session(session_id)
            if s:
                s.spider_progress = pct
                update_session(s)
            if pct < 100:
                push_progress(session_id, f"🕷 Spider crawling… {pct}% — discovering endpoints")
            else:
                push_progress(session_id, "✅ Spider complete — all endpoints mapped")

        spider_id = await loop.run_in_executor(None, zap_client.run_spider, session.target_url)
        session = get_session(session_id)
        session.zap_spider_id = spider_id
        update_session(session)
        await loop.run_in_executor(None, zap_client.wait_for_spider, spider_id, _spider_progress)

        push_progress(session_id, "🔍 Running OWASP ZAP passive vulnerability scan…")
        raw_alerts = await loop.run_in_executor(None, zap_client.get_passive_alerts, session.target_url)
        push_progress(session_id, f"🤖 Codex analysing {len(raw_alerts)} ZAP alerts for real vulnerabilities…")
        findings = await loop.run_in_executor(None, ai_agent.analyze_zap_alerts, raw_alerts)
        push_progress(session_id, f"✅ Vulnerability assessment complete — {len(findings)} findings identified")
        session = get_session(session_id)
        session.va_findings = findings
        session.state = ScanState.AWAITING_GREENLIGHT
        update_session(session)
        audit_logger.log(session_id, "va_complete", "system",
                         f"VA found {len(findings)} vulnerabilities")
    except Exception as exc:
        logger.exception("VA failed for %s", session_id)
        s = get_session(session_id)
        s.state = ScanState.ERROR
        s.error_message = str(exc)
        update_session(s)


async def _run_pt_phase(session_id: str) -> None:
    session = get_session(session_id)
    if not session:
        return
    try:
        session.state = ScanState.PT_RUNNING
        update_session(session)
        loop = asyncio.get_event_loop()
        approved = [f for f in session.va_findings if f.id in session.approved_finding_ids]
        push_progress(session_id, f"🚀 Launching {len(approved)} parallel Codex PT agents…")
        policy = next((f.pt_category for f in approved if f.pt_category), "Default Policy")
        push_progress(session_id, f"⚔ Starting ZAP active scan with policy: {policy}…")
        scan_id = await loop.run_in_executor(None, zap_client.run_active_scan, session.target_url, policy)
        session = get_session(session_id)
        session.zap_scan_id = scan_id
        update_session(session)

        def _scan_progress(pct: int):
            s = get_session(session_id)
            if s:
                s.scan_progress = pct
                update_session(s)
            if pct < 100:
                push_progress(session_id, f"⚔ Active scan running… {pct}% — probing for vulnerabilities")
            else:
                push_progress(session_id, "✅ Active scan complete — collecting evidence")

        await loop.run_in_executor(None, zap_client.wait_for_active_scan, scan_id, _scan_progress)
        push_progress(session_id, "🤖 Codex agents verifying each finding independently…")
        pt_alerts = await loop.run_in_executor(None, zap_client.get_active_alerts, session.target_url)

        agent_statuses = [
            AgentStatus(agent_id=str(uuid.uuid4())[:8], finding_id=f.id,
                        finding_name=f.name, severity=f.severity, status="pending", log="Queued…")
            for f in approved
        ]
        session = get_session(session_id)
        session.agent_statuses = agent_statuses
        update_session(session)

        def _upd(updated: AgentStatus):
            s = get_session(session_id)
            for i, a in enumerate(s.agent_statuses):
                if a.agent_id == updated.agent_id:
                    s.agent_statuses[i] = updated
                    break
            update_session(s)

        tasks = [loop.run_in_executor(None, ai_agent.run_single_pt_agent,
                                      approved[i], pt_alerts, agent_statuses[i], _upd)
                 for i in range(len(approved))]
        pt_results = list(await asyncio.gather(*tasks))
        session = get_session(session_id)
        session.pt_results = pt_results
        narrative = await loop.run_in_executor(None, ai_agent.generate_report_narrative, session)
        session.narrative = narrative
        report_path = REPORTS_DIR / f"{session_id}.html"
        report_path.write_text(generate_html_report(session), encoding="utf-8")
        session.state = ScanState.REPORT_READY
        finalize_session(session)
        confirmed = sum(1 for r in pt_results if r.status == "confirmed")
        audit_logger.log(session_id, "report_ready", "system",
                         f"PT done. {confirmed}/{len(pt_results)} vulnerabilities confirmed.")
    except Exception as exc:
        logger.exception("PT failed for %s", session_id)
        s = get_session(session_id)
        s.state = ScanState.ERROR
        s.error_message = str(exc)
        update_session(s)


# ── UNIVERSAL ROUTES ───────────────────────────────────────────────────────

@app.get("/api/scan/{session_id}/status")
async def get_status(session_id: str):
    session = get_session(session_id)
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")
    return {
        "session_id": session.session_id, "phase": session.phase, "state": session.state,
        "initiated_by": session.initiated_by, "greenlighted_by": session.greenlighted_by,
        "error_message": session.error_message,
        "finding_count": len(session.va_findings) + len(session.sast_findings),
        "reviewed_count": len(session.reviewed_finding_ids),
        # Live progress data
        "progress_log": session.progress_log[-12:],   # last 12 entries only
        "spider_progress": session.spider_progress,
        "scan_progress": session.scan_progress,
    }


@app.get("/api/scan/{session_id}/results")
async def get_results(session_id: str):
    session = get_session(session_id)
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")
    return {
        "phase": session.phase,
        "threat_model": session.threat_model.model_dump() if session.threat_model else None,
        "sast_findings": [f.model_dump() for f in session.sast_findings],
        "va_findings": [f.model_dump() for f in session.va_findings],
    }


@app.post("/api/scan/{session_id}/review-finding")
async def review_finding(session_id: str, body: ReviewFindingRequest):
    session = get_session(session_id)
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")
    if body.finding_id not in session.reviewed_finding_ids:
        session.reviewed_finding_ids.append(body.finding_id)
        update_session(session)
        audit_logger.log(session_id, "finding_reviewed", body.reviewer,
                         f"Finding {body.finding_id[:8]} individually reviewed")
    return {"reviewed": len(session.reviewed_finding_ids)}


@app.post("/api/scan/{session_id}/greenlight")
async def greenlight(session_id: str, body: GreenlightRequest, background_tasks: BackgroundTasks):
    session = get_session(session_id)
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")
    if session.state != ScanState.AWAITING_GREENLIGHT:
        raise HTTPException(status_code=409, detail=f"Cannot greenlight in state: {session.state}")
    if not body.risk_acknowledgement:
        raise HTTPException(status_code=400, detail="Risk acknowledgement is required")
    if not body.approved_finding_ids:
        raise HTTPException(status_code=400, detail="At least one finding must be selected")
    if body.greenlighted_by.strip().lower() == session.initiated_by.strip().lower():
        raise HTTPException(status_code=403,
                            detail="4-eyes principle: approver cannot be the same person as the initiator")

    session.greenlighted_by = body.greenlighted_by
    session.approved_finding_ids = body.approved_finding_ids
    session.state = ScanState.GREENLIGHTED
    update_session(session)
    audit_logger.log(session_id, "greenlight_approved", body.greenlighted_by,
                     f"Greenlighted {len(body.approved_finding_ids)} findings. Risk acknowledged.")

    if session.phase == SDLCPhase.DEPLOYMENT:
        background_tasks.add_task(_run_pt_phase, session_id)
    else:
        async def _gen():
            s = get_session(session_id)
            loop = asyncio.get_event_loop()
            narrative = await loop.run_in_executor(None, ai_agent.generate_report_narrative, s)
            s.narrative = narrative
            report_path = REPORTS_DIR / f"{session_id}.html"
            report_path.write_text(generate_html_report(s), encoding="utf-8")
            s.state = ScanState.REPORT_READY
            finalize_session(s)
            audit_logger.log(session_id, "report_ready", "system", "Report generated")
        background_tasks.add_task(_gen)

    return {"session_id": session_id, "state": session.state}


@app.post("/api/scan/{session_id}/skip-pt")
async def skip_pt(session_id: str, background_tasks: BackgroundTasks):
    session = get_session(session_id)
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")

    async def _gen():
        s = get_session(session_id)
        loop = asyncio.get_event_loop()
        narrative = await loop.run_in_executor(None, ai_agent.generate_report_narrative, s)
        s.narrative = narrative
        report_path = REPORTS_DIR / f"{session_id}.html"
        report_path.write_text(generate_html_report(s), encoding="utf-8")
        s.state = ScanState.REPORT_READY
        finalize_session(s)
        audit_logger.log(session_id, "pt_skipped", "user", "PT skipped — report generated without active scan")

    background_tasks.add_task(_gen)
    return {"session_id": session_id}


@app.get("/api/scan/{session_id}/agent-statuses")
async def get_agent_statuses(session_id: str):
    session = get_session(session_id)
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")
    return {"agents": [a.model_dump() for a in session.agent_statuses]}


@app.get("/api/scan/{session_id}/pt-results")
async def get_pt_results(session_id: str):
    session = get_session(session_id)
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")
    return {"results": [r.model_dump() for r in session.pt_results]}


@app.get("/api/scan/{session_id}/audit-log")
async def get_audit_log(session_id: str):
    session = get_session(session_id)
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")
    return {"audit_log": [e.model_dump() for e in session.audit_log]}


@app.get("/api/scan/{session_id}/report", response_class=HTMLResponse)
async def get_report(session_id: str):
    session = get_session(session_id)
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")
    if session.state != ScanState.REPORT_READY:
        raise HTTPException(status_code=202, detail="Report not yet ready")
    report_path = REPORTS_DIR / f"{session_id}.html"
    return HTMLResponse(content=report_path.read_text(encoding="utf-8"))


@app.get("/api/scan/{session_id}/report/download")
async def download_report(session_id: str):
    session = get_session(session_id)
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")
    report_path = REPORTS_DIR / f"{session_id}.html"
    return FileResponse(path=str(report_path), filename=f"vapt_report_{session_id[:8]}.html", media_type="text/html")
