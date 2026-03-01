import { Router } from "express";
import { v4 as uuidv4 } from "uuid";
import { ScanStore } from "../store/scanStore.js";
import { ScanOrchestrator } from "../agent/orchestrator.js";
import type { WSManager } from "../websocket.js";

export function createScanRouter(wsManager: WSManager): Router {
  const router = Router();

  // POST /api/scan/start
  router.post("/start", (req, res) => {
    const { url } = req.body as { url?: string };
    if (!url) {
      res.status(400).json({ error: "url is required" });
      return;
    }

    try {
      new URL(url); // validate URL
    } catch {
      res.status(400).json({ error: "Invalid URL" });
      return;
    }

    const scanId = uuidv4();
    ScanStore.create(scanId, url);

    const orchestrator = new ScanOrchestrator(scanId);

    // Wire orchestrator events → WebSocket broadcasts
    orchestrator.on("phase_started", ({ phase }: { phase: string }) => {
      wsManager.broadcast(scanId, { type: "phase.started", phase });
    });
    orchestrator.on("phase_complete", ({ phase, data }: { phase: string; data?: unknown }) => {
      wsManager.broadcast(scanId, { type: "phase.complete", phase, data });
    });
    orchestrator.on(
      "agent_assigned",
      ({ agentId, candidate }: { agentId: string; candidate: import("../store/scanStore.js").ExploitCandidate }) => {
        wsManager.broadcast(scanId, {
          type: "agent.assigned",
          agentId,
          candidateType: candidate.type,
          endpoint: candidate.endpoint,
          param: candidate.param,
        });
      }
    );
    orchestrator.on("agent_skipped", ({ agentId }: { agentId: string }) => {
      wsManager.broadcast(scanId, { type: "agent.skipped", agentId });
    });
    orchestrator.on("agent_done", ({ agentId }: { agentId: string }) => {
      wsManager.broadcast(scanId, { type: "agent.done", agentId });
    });
    orchestrator.on("agent_message", ({ agentId, text }: { agentId?: string; text: string }) => {
      wsManager.broadcast(scanId, { type: "agent.message", agentId, text });
    });
    orchestrator.on("tool_call", ({ agentId, tool, args }: { agentId?: string; tool: string; args: unknown }) => {
      wsManager.broadcast(scanId, { type: "tool.called", agentId, tool, args });
    });
    orchestrator.on("tool_result", ({ agentId, tool, result }: { agentId?: string; tool: string; result: string }) => {
      wsManager.broadcast(scanId, { type: "tool.result", agentId, tool, result });
    });
    orchestrator.on("finding_discovered", (finding: unknown) => {
      wsManager.broadcast(scanId, { type: "finding.discovered", finding });
    });
    orchestrator.on(
      "approval_required",
      (req: import("../agent/approvalGate.js").ApprovalRequest) => {
        wsManager.broadcast(scanId, {
          type: "approval.required",
          approvalId: req.id,
          scanId: req.scanId,
          requestType: req.type,
          message: req.message,
          data: req.data,
        });
      }
    );
    orchestrator.on("approval_resolved", ({ id, approved }: { id: string; approved: boolean }) => {
      wsManager.broadcast(scanId, { type: "approval.resolved", approvalId: id, approved });
    });
    orchestrator.on("scan_complete", () => {
      wsManager.broadcast(scanId, { type: "scan.complete" });
    });
    orchestrator.on("scan_error", ({ error }: { error: string }) => {
      wsManager.broadcast(scanId, { type: "scan.error", error });
    });

    // Store gate reference for approval route
    ScanStore.update(scanId, { gate: orchestrator.approvalGate });

    // Run scan in background (don't await)
    orchestrator.run(url).catch((err) => {
      console.error(`Scan ${scanId} crashed:`, err);
    });

    wsManager.broadcast(scanId, { type: "scan.started", scanId, url });
    res.json({ scanId });
  });

  // GET /api/scan/:scanId/status
  router.get("/:scanId/status", (req, res) => {
    const scan = ScanStore.get(req.params.scanId);
    if (!scan) {
      res.status(404).json({ error: "Scan not found" });
      return;
    }
    res.json({
      id: scan.id,
      url: scan.url,
      status: scan.status,
      phase: scan.phase,
      findings: scan.findings,
      error: scan.error,
    });
  });

  return router;
}
