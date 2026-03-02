import asyncio
import json
import os
import shutil
import tempfile
import uuid
from fastapi import APIRouter, HTTPException, Depends
from auth import get_current_user
from fastapi.responses import HTMLResponse, Response
from sse_starlette.sse import EventSourceResponse
from models import ScanRequest, ScanState, ScanStatus, AgentResult
from pipeline.crawler import crawl
from pipeline.scanner import build_surface_notes, audit_headers
from pipeline.vuln_scanner import run_nuclei
from pipeline.code_cloner import clone_repo
from pipeline.sast_scanner import run_sast
from agents.recon_agent import run_recon_agent
from agents.orchestrator import run_all_exploit_agents
from reporters.report_compiler import compile_report
from supabase_client import get_supabase

router = APIRouter()

# In-memory store: scan_id → ScanState
_scans: dict[str, ScanState] = {}
# Event queues: scan_id → asyncio.Queue
_event_queues: dict[str, asyncio.Queue] = {}


async def _sb_update_scan(scan_id: str, updates: dict):
    """Fire-and-forget Supabase scan row update."""
    try:
        sb = await get_supabase()
        await sb.table("scans").update(updates).eq("id", scan_id).execute()
    except Exception:
        pass


async def _sb_push_event(scan_id: str, event: str, data: dict):
    """Fire-and-forget Supabase scan_events insert."""
    try:
        sb = await get_supabase()
        await sb.table("scan_events").insert({
            "scan_id": scan_id,
            "event": event,
            "data": data,
        }).execute()
    except Exception:
        pass


def _push(scan_id: str, event: str, data: dict):
    q = _event_queues.get(scan_id)
    if q:
        q.put_nowait({"event": event, "data": json.dumps(data)})
    asyncio.create_task(_sb_push_event(scan_id, event, data))


async def _run_pipeline(scan_id: str):
    state = _scans[scan_id]
    sast_tmp = None
    try:
        # ── Phase 1: Crawl ──────────────────────────────────────────────
        _push(scan_id, "phase", {"phase": "CRAWLING", "message": "Crawling target..."})
        surface = await crawl(state.target_url)

        # ── Phase 2: Active Vulnerability Scan (Nuclei) ─────────────────
        state.status = ScanStatus.SCANNING
        asyncio.create_task(_sb_update_scan(scan_id, {"status": "SCANNING"}))
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

        # ── Phase 3 (optional): SAST ────────────────────────────────────
        if state.sast_config:
            sast_tmp = tempfile.mkdtemp(prefix=f"sast_{scan_id[:8]}_")
            try:
                state.status = ScanStatus.SAST_CLONING
                _push(scan_id, "phase", {"phase": "SAST_CLONING", "message": "Cloning repository for static analysis..."})
                repo_path = await clone_repo(
                    state.sast_config.repo_url,
                    state.sast_config.pat,
                    os.path.join(sast_tmp, "repo"),
                )

                state.status = ScanStatus.SAST_ANALYZING
                _push(scan_id, "phase", {"phase": "SAST_ANALYZING", "message": "Running static analysis (Semgrep + npm audit)..."})
                sast_findings = await run_sast(repo_path)
                state.sast_findings = sast_findings
                _push(scan_id, "sast_findings", {
                    "count": len(sast_findings),
                    "findings": [
                        {
                            "tool": f.tool,
                            "rule_id": f.rule_id,
                            "severity": f.severity.value,
                            "file_path": f.file_path,
                            "line_number": f.line_number,
                            "message": f.message,
                        }
                        for f in sast_findings
                    ],
                })
            except Exception as sast_err:
                # SAST errors are non-fatal — log and continue
                _push(scan_id, "phase", {"phase": "SAST_ANALYZING", "message": f"SAST warning: {sast_err} — continuing with DAST findings only."})

        # ── Phase 4: Recon Agent ────────────────────────────────────────
        # Persist surface report
        asyncio.create_task(_sb_update_scan(scan_id, {"surface_report": surface.model_dump()}))

        # ── Phase 3: Recon Agent ────────────────────────────────────────
        _push(scan_id, "phase", {"phase": "SCANNING", "message": "Recon Agent assigning vulnerability investigations..."})
        hypotheses = await run_recon_agent(surface, state.sast_findings)
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

        # Persist hypotheses
        async def _insert_hypotheses():
            try:
                sb = await get_supabase()
                rows = [
                    {
                        "id": h.id,
                        "scan_id": scan_id,
                        "title": h.title,
                        "target_url": h.target_url,
                        "attack_surface": h.attack_surface,
                        "technique": h.technique,
                        "attack_hints": h.attack_hints,
                        "rationale": h.rationale,
                        "severity_estimate": h.severity_estimate.value,
                    }
                    for h in hypotheses
                ]
                await sb.table("hypotheses").insert(rows).execute()
            except Exception:
                pass
        asyncio.create_task(_insert_hypotheses())

        # ── Phase 4: Await human approval ──────────────────────────────
        state.status = ScanStatus.AWAITING_APPROVAL
        asyncio.create_task(_sb_update_scan(scan_id, {"status": "AWAITING_APPROVAL"}))
        _push(scan_id, "phase", {"phase": "AWAITING_APPROVAL", "message": "Awaiting user authorization to proceed..."})

        # Wait for approval signal (set by /approve endpoint)
        while state.status == ScanStatus.AWAITING_APPROVAL:
            await asyncio.sleep(0.5)

        if state.status == ScanStatus.ERROR:
            _push(scan_id, "error", {"message": "Scan cancelled by user"})
            return

        # ── Phase 5: Exploit Agents ─────────────────────────────────────
        asyncio.create_task(_sb_update_scan(scan_id, {"status": "EXPLOITING"}))
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

            async def _insert_agent_result():
                try:
                    sb = await get_supabase()
                    await sb.table("agent_results").insert({
                        "scan_id": scan_id,
                        "hypothesis_id": result.hypothesis_id,
                        "hypothesis_title": result.hypothesis_title,
                        "technique": result.technique,
                        "status": result.status.value,
                        "severity": result.severity.value,
                        "steps": [s.model_dump() for s in result.steps],
                        "summary": result.summary,
                        "remediation": result.remediation,
                        "cvss_score": result.cvss_score,
                        "screenshot_paths": result.screenshot_paths,
                        "false_positive_reason": result.false_positive_reason,
                    }).execute()
                except Exception:
                    pass
            asyncio.create_task(_insert_agent_result())

        results = await run_all_exploit_agents(hypotheses, state, agent_done_callback)
        state.agent_results = results

        # ── Phase 6: Done ───────────────────────────────────────────────
        state.status = ScanStatus.DONE
        confirmed = sum(1 for r in results if r.status.value == "CONFIRMED")
        asyncio.create_task(_sb_update_scan(scan_id, {"status": "DONE"}))
        _push(scan_id, "phase", {"phase": "DONE", "message": "All agents complete."})
        _push(scan_id, "done", {
            "total": len(results),
            "confirmed": confirmed,
            "unconfirmed": len(results) - confirmed,
        })

    except Exception as e:
        state.status = ScanStatus.ERROR
        state.error = str(e)
        asyncio.create_task(_sb_update_scan(scan_id, {"status": "ERROR", "error": str(e)}))
        _push(scan_id, "error", {"message": str(e)})
    finally:
        # Clean up cloned repo temp dir
        if sast_tmp and os.path.exists(sast_tmp):
            shutil.rmtree(sast_tmp, ignore_errors=True)
        # Signal SSE stream to end after short delay
        await asyncio.sleep(2)
        q = _event_queues.get(scan_id)
        if q:
            q.put_nowait(None)  # sentinel


@router.post("/scan/start")
async def start_scan(request: ScanRequest, _user: str = Depends(get_current_user)):
    scan_id = str(uuid.uuid4())
    state = ScanState(
        scan_id=scan_id,
        target_url=str(request.url),
        sast_config=request.sast_config,
        user_id=_user
    )
    _scans[scan_id] = state
    _event_queues[scan_id] = asyncio.Queue()

    try:
        sb = await get_supabase()
        await sb.table("scans").insert({
            "id": scan_id,
            "user_id": _user,
            "target_url": str(request.url),
            "status": "CRAWLING",
        }).execute()
    except Exception:
        pass

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
async def approve_scan(scan_id: str, _user: str = Depends(get_current_user)):
    state = _scans.get(scan_id)
    if not state:
        raise HTTPException(status_code=404, detail="Scan not found")
    if state.status != ScanStatus.AWAITING_APPROVAL:
        raise HTTPException(status_code=400, detail="Scan is not awaiting approval")
    state.status = ScanStatus.EXPLOITING
    asyncio.create_task(_sb_update_scan(scan_id, {"status": "EXPLOITING"}))
    return {"ok": True}


@router.post("/scan/{scan_id}/cancel")
async def cancel_scan(scan_id: str, _user: str = Depends(get_current_user)):
    state = _scans.get(scan_id)
    if not state:
        raise HTTPException(status_code=404, detail="Scan not found")
    state.status = ScanStatus.ERROR
    state.error = "Cancelled by user"
    asyncio.create_task(_sb_update_scan(scan_id, {"status": "ERROR", "error": "Cancelled by user"}))
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
async def get_report(scan_id: str, _user: str = Depends(get_current_user)):
    state = _scans.get(scan_id)
    if not state:
        raise HTTPException(status_code=404, detail="Scan not found")
    html = await compile_report(state)
    return HTMLResponse(content=html)


@router.get("/scan/{scan_id}/report/pdf")
async def get_report_pdf(scan_id: str, _user: str = Depends(get_current_user)):
    state = _scans.get(scan_id)
    if not state:
        raise HTTPException(status_code=404, detail="Scan not found")
    html = await compile_report(state)
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

        # Upload PDF to Supabase Storage (fire-and-forget)
        async def _upload_pdf():
            try:
                sb = await get_supabase()
                storage_path = f"{_user}/{scan_id}.pdf"
                await sb.storage.from_("reports").upload(
                    storage_path,
                    pdf_bytes,
                    {"content-type": "application/pdf", "upsert": "true"},
                )
                signed = await sb.storage.from_("reports").create_signed_url(storage_path, 60 * 60 * 24 * 365)
                signed_url = signed.signed_url if hasattr(signed, "signed_url") else signed.get("signedURL", "")
                if signed_url:
                    await sb.table("scans").update({"report_pdf_url": signed_url}).eq("id", scan_id).execute()
            except Exception:
                pass
        asyncio.create_task(_upload_pdf())

        return Response(
            content=pdf_bytes,
            media_type="application/pdf",
            headers={"Content-Disposition": f"inline; filename=pentest-report-{scan_id[:8]}.pdf"},
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"PDF generation failed: {e}")


@router.get("/scans")
async def list_scans(_user: str = Depends(get_current_user)):
    """Return the authenticated user's scan history (newest first)."""
    try:
        sb = await get_supabase()
        result = await (
            sb.table("scans")
            .select("id, target_url, status, report_pdf_url, created_at, updated_at")
            .eq("user_id", _user)
            .order("created_at", desc=True)
            .limit(50)
            .execute()
        )
        return {"scans": result.data or []}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
