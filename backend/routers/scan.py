import asyncio
import json
import uuid
from fastapi import APIRouter, HTTPException
from fastapi.responses import HTMLResponse, Response
from sse_starlette.sse import EventSourceResponse
from models import (
    ScanRequest, ScanState, ScanStatus, ScanMode, SASTStatus, AgentResult
)
from pipeline.crawler import crawl
from pipeline.scanner import build_surface_notes, audit_headers
from pipeline.vuln_scanner import run_nuclei
from agents.recon_agent import run_recon_agent
from agents.orchestrator import run_all_exploit_agents
from agents.sast_agent import run_sast_agent
from reporters.report_compiler import compile_report

router = APIRouter()

# In-memory stores
_scans: dict[str, ScanState] = {}
_event_queues: dict[str, asyncio.Queue] = {}
# PATs stored separately to avoid logging them in scan state
_pats: dict[str, str] = {}


def _push(scan_id: str, event: str, data: dict):
    q = _event_queues.get(scan_id)
    if q:
        q.put_nowait({"event": event, "data": json.dumps(data)})


# ── DAST pipeline (existing logic, extracted) ─────────────────────────────────
async def _run_dast_pipeline(scan_id: str):
    state = _scans[scan_id]
    try:
        # Phase 1: Crawl
        _push(scan_id, "phase", {"phase": "CRAWLING", "message": "Crawling target..."})
        surface = await crawl(state.target_url)

        # Phase 2: Active Vulnerability Scan (Nuclei)
        state.status = ScanStatus.SCANNING
        _push(scan_id, "phase", {"phase": "SCANNING", "message": "Running Nuclei active vulnerability scan..."})
        scanner_findings = await run_nuclei(state.target_url)
        surface.scanner_findings = scanner_findings

        state.surface_report = surface
        header_findings = audit_headers(surface)
        _push(scan_id, "surface", {
            "urls_found": len(surface.discovered_urls),
            "forms_found": len(surface.forms),
            "tech_stack": surface.tech_stack,
            "discovered_urls": surface.discovered_urls[:50],
            "header_issues": len(header_findings),
            "scanner_findings_count": len(scanner_findings),
        })

        # Phase 3: Recon Agent
        _push(scan_id, "phase", {"phase": "SCANNING", "message": "Recon Agent assigning vulnerability investigations..."})
        hypotheses = await run_recon_agent(surface)
        state.hypotheses = hypotheses
        _push(scan_id, "hypotheses", {
            "count": len(hypotheses),
            "hypotheses": [
                {
                    "id": h.id,
                    "title": h.title,
                    "technique": h.technique,
                    "severity": h.severity_estimate.value,
                    "target_url": h.target_url,
                    "attack_surface": h.attack_surface,
                }
                for h in hypotheses
            ],
        })

        # Phase 4: Await human approval
        state.status = ScanStatus.AWAITING_APPROVAL
        _push(scan_id, "phase", {"phase": "AWAITING_APPROVAL", "message": "Awaiting user authorization to proceed..."})

        while state.status == ScanStatus.AWAITING_APPROVAL:
            await asyncio.sleep(0.5)

        if state.status == ScanStatus.ERROR:
            _push(scan_id, "error", {"message": "Scan cancelled by user"})
            return

        # Phase 5: Exploit Agents
        _push(scan_id, "phase", {"phase": "EXPLOITING", "message": f"Launching {len(hypotheses)} vulnerability investigation agents..."})

        async def agent_done_callback(result: AgentResult):
            state.agent_results.append(result)
            _push(scan_id, "agent_result", {
                "hypothesis_id": result.hypothesis_id,
                "title": result.hypothesis_title,
                "status": result.status.value,
                "severity": result.severity.value,
                "technique": result.technique,
                "steps_count": len(result.steps),
            })

        results = await run_all_exploit_agents(hypotheses, state, agent_done_callback)
        state.agent_results = results

    except Exception as e:
        state.status = ScanStatus.ERROR
        state.error = str(e)
        _push(scan_id, "error", {"message": str(e)})
        raise


# ── SAST pipeline ─────────────────────────────────────────────────────────────
async def _run_sast_pipeline(scan_id: str):
    state = _scans[scan_id]
    pat = _pats.get(scan_id, "")
    try:
        state.sast_status = SASTStatus.RUNNING
        _push(scan_id, "sast_status", {"status": "RUNNING", "message": "Analyzing repository..."})

        owner, repo_name = (state.github_repo or "").split("/", 1)
        findings = await run_sast_agent(
            pat=pat,
            owner=owner,
            repo=repo_name,
            push_fn=lambda event, data: _push(scan_id, event, data),
        )
        state.sast_findings = findings
        state.sast_status = SASTStatus.DONE
        _push(scan_id, "sast_status", {
            "status": "DONE",
            "count": len(findings),
            "message": f"SAST complete — {len(findings)} finding(s) identified",
        })

    except Exception as e:
        state.sast_status = SASTStatus.ERROR
        _push(scan_id, "sast_status", {"status": "ERROR", "message": str(e)})


# ── Combined pipeline ─────────────────────────────────────────────────────────
async def _run_pipeline(scan_id: str):
    state = _scans[scan_id]
    try:
        tasks = []
        if state.scan_mode in (ScanMode.DAST, ScanMode.BOTH):
            tasks.append(_run_dast_pipeline(scan_id))
        if state.scan_mode in (ScanMode.SAST, ScanMode.BOTH):
            tasks.append(_run_sast_pipeline(scan_id))

        results = await asyncio.gather(*tasks, return_exceptions=True)

        # Propagate any unhandled exceptions
        for r in results:
            if isinstance(r, Exception) and not isinstance(r, asyncio.CancelledError):
                if state.status != ScanStatus.ERROR:
                    state.status = ScanStatus.ERROR
                    state.error = str(r)

        if state.status != ScanStatus.ERROR:
            state.status = ScanStatus.DONE
            dast_confirmed = sum(1 for r in state.agent_results if r.status.value == "CONFIRMED")
            _push(scan_id, "phase", {"phase": "DONE", "message": "All agents complete."})
            _push(scan_id, "done", {
                "total": len(state.agent_results),
                "confirmed": dast_confirmed,
                "unconfirmed": len(state.agent_results) - dast_confirmed,
                "sast_count": len(state.sast_findings),
            })

    except Exception as e:
        state.status = ScanStatus.ERROR
        state.error = str(e)
        _push(scan_id, "error", {"message": str(e)})
    finally:
        # Clean up PAT from memory
        _pats.pop(scan_id, None)
        await asyncio.sleep(2)
        q = _event_queues.get(scan_id)
        if q:
            q.put_nowait(None)  # sentinel to close SSE stream


# ── Endpoints ─────────────────────────────────────────────────────────────────

@router.post("/scan/start")
async def start_scan(request: ScanRequest):
    # Validate required fields per mode
    if request.mode in (ScanMode.DAST, ScanMode.BOTH) and not request.url:
        raise HTTPException(400, "Target URL is required for DAST and Both modes")
    if request.mode in (ScanMode.SAST, ScanMode.BOTH):
        if not request.github_pat:
            raise HTTPException(400, "GitHub PAT is required for SAST and Both modes")
        if not request.github_repo or "/" not in request.github_repo:
            raise HTTPException(400, "GitHub repo must be in 'owner/repo' format")

    scan_id = str(uuid.uuid4())
    state = ScanState(
        scan_id=scan_id,
        target_url=str(request.url) if request.url else None,
        scan_mode=request.mode,
        github_repo=request.github_repo,
    )
    _scans[scan_id] = state
    _event_queues[scan_id] = asyncio.Queue()

    if request.github_pat:
        _pats[scan_id] = request.github_pat

    asyncio.create_task(_run_pipeline(scan_id))
    return {"scan_id": scan_id}


@router.get("/scan/{scan_id}/events")
async def scan_events(scan_id: str):
    if scan_id not in _scans:
        raise HTTPException(status_code=404, detail="Scan not found")

    queue = _event_queues.get(scan_id)
    if not queue:
        raise HTTPException(status_code=404, detail="Event queue not found")

    async def generator():
        while True:
            item = await queue.get()
            if item is None:
                break
            yield {"event": item["event"], "data": item["data"]}

    return EventSourceResponse(generator())


@router.post("/scan/{scan_id}/approve")
async def approve_scan(scan_id: str):
    state = _scans.get(scan_id)
    if not state:
        raise HTTPException(status_code=404, detail="Scan not found")
    if state.status != ScanStatus.AWAITING_APPROVAL:
        raise HTTPException(status_code=400, detail="Scan is not awaiting approval")
    state.status = ScanStatus.EXPLOITING
    return {"ok": True}


@router.post("/scan/{scan_id}/cancel")
async def cancel_scan(scan_id: str):
    state = _scans.get(scan_id)
    if not state:
        raise HTTPException(status_code=404, detail="Scan not found")
    state.status = ScanStatus.ERROR
    state.error = "Cancelled by user"
    return {"ok": True}


@router.get("/scan/{scan_id}/status")
async def get_status(scan_id: str):
    state = _scans.get(scan_id)
    if not state:
        raise HTTPException(status_code=404, detail="Scan not found")
    return {
        "scan_id": state.scan_id,
        "status": state.status.value,
        "scan_mode": state.scan_mode.value,
        "sast_status": state.sast_status.value,
        "hypotheses_count": len(state.hypotheses),
        "results_count": len(state.agent_results),
        "sast_findings_count": len(state.sast_findings),
    }


@router.get("/scan/{scan_id}/sast-findings")
async def get_sast_findings(scan_id: str):
    state = _scans.get(scan_id)
    if not state:
        raise HTTPException(status_code=404, detail="Scan not found")
    return {
        "status": state.sast_status.value,
        "findings": [f.model_dump() for f in state.sast_findings],
    }


@router.get("/scan/{scan_id}/report")
async def get_report(scan_id: str):
    state = _scans.get(scan_id)
    if not state:
        raise HTTPException(status_code=404, detail="Scan not found")
    html = compile_report(state)
    return HTMLResponse(content=html)


@router.get("/scan/{scan_id}/report/pdf")
async def get_report_pdf(scan_id: str):
    state = _scans.get(scan_id)
    if not state:
        raise HTTPException(status_code=404, detail="Scan not found")
    html = compile_report(state)
    try:
        from playwright.async_api import async_playwright
        async with async_playwright() as p:
            browser = await p.chromium.launch(headless=True)
            page = await browser.new_page()
            await page.set_content(html, wait_until="networkidle")
            pdf_bytes = await page.pdf(
                format="A4",
                margin={"top": "0", "bottom": "0", "left": "0", "right": "0"},
                print_background=True,
            )
            await browser.close()
        return Response(
            content=pdf_bytes,
            media_type="application/pdf",
            headers={"Content-Disposition": f"inline; filename=pentest-report-{scan_id[:8]}.pdf"},
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"PDF generation failed: {e}")
