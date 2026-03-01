import asyncio
import json
import uuid
from typing import AsyncGenerator
from fastapi import APIRouter, HTTPException
from fastapi.responses import HTMLResponse, StreamingResponse, Response
from sse_starlette.sse import EventSourceResponse
from models import ScanRequest, ScanState, ScanStatus, AgentResult
from pipeline.crawler import crawl
from pipeline.scanner import build_surface_notes, audit_headers
from pipeline.vuln_scanner import run_nuclei
from agents.recon_agent import run_recon_agent
from agents.orchestrator import run_all_exploit_agents
from reporters.report_compiler import compile_report

router = APIRouter()

# In-memory store: scan_id → ScanState
_scans: dict[str, ScanState] = {}
# Event queues: scan_id → list of SSE events
_event_queues: dict[str, asyncio.Queue] = {}


def _push(scan_id: str, event: str, data: dict):
    q = _event_queues.get(scan_id)
    if q:
        q.put_nowait({"event": event, "data": json.dumps(data)})


async def _run_pipeline(scan_id: str):
    state = _scans[scan_id]
    try:
        # ── Phase 1: Crawl ──────────────────────────────────────────────
        _push(scan_id, "phase", {"phase": "CRAWLING", "message": "Crawling target..."})
        surface = await crawl(state.target_url)

        # ── Phase 2: Active Vulnerability Scan (Nuclei) ─────────────────
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

        # ── Phase 3: Recon Agent ────────────────────────────────────────
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

        # ── Phase 4: Await human approval ──────────────────────────────
        state.status = ScanStatus.AWAITING_APPROVAL
        _push(scan_id, "phase", {"phase": "AWAITING_APPROVAL", "message": "Awaiting user authorization to proceed..."})

        # Wait for approval signal (set by /approve endpoint)
        while state.status == ScanStatus.AWAITING_APPROVAL:
            await asyncio.sleep(0.5)

        if state.status == ScanStatus.ERROR:
            _push(scan_id, "error", {"message": "Scan cancelled by user"})
            return

        # ── Phase 5: Exploit Agents ─────────────────────────────────────
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

        # ── Phase 6: Done ───────────────────────────────────────────────
        state.status = ScanStatus.DONE
        confirmed = sum(1 for r in results if r.status.value == "CONFIRMED")
        _push(scan_id, "phase", {"phase": "DONE", "message": "All agents complete."})
        _push(scan_id, "done", {
            "total": len(results),
            "confirmed": confirmed,
            "unconfirmed": len(results) - confirmed,
        })

    except Exception as e:
        state.status = ScanStatus.ERROR
        state.error = str(e)
        _push(scan_id, "error", {"message": str(e)})
    finally:
        # Signal SSE stream to end after short delay
        await asyncio.sleep(2)
        q = _event_queues.get(scan_id)
        if q:
            q.put_nowait(None)  # sentinel


@router.post("/scan/start")
async def start_scan(request: ScanRequest):
    scan_id = str(uuid.uuid4())
    state = ScanState(scan_id=scan_id, target_url=str(request.url))
    _scans[scan_id] = state
    _event_queues[scan_id] = asyncio.Queue()
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
        "hypotheses_count": len(state.hypotheses),
        "results_count": len(state.agent_results),
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
