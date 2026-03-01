import { EventEmitter } from "events";
import { Codex } from "@openai/codex-sdk";
import { homedir } from "os";
import { mkdirSync, writeFileSync } from "fs";
import path from "path";
import { ApprovalGate } from "./approvalGate.js";
import { PHASE_PROMPTS } from "./phases.js";
import { VulnAgent } from "./vulnAgent.js";
import { ScanStore } from "../store/scanStore.js";
import type { ExploitCandidate } from "../store/scanStore.js";

function registerMcpServer(): void {
  const codexDir = path.join(homedir(), ".codex");
  mkdirSync(codexDir, { recursive: true });
  const mcpServerPath = path.resolve(
    new URL(".", import.meta.url).pathname,
    "../../../mcp-server/dist/index.js"
  );
  const configPath = path.join(codexDir, "config.toml");
  const configContent = `[mcp_servers.vapt-tools]\ncommand = "node"\nargs = ["${mcpServerPath}"]\n`;
  writeFileSync(configPath, configContent, "utf8");
}

export type OrchestratorEvent =
  | { type: "phase_started"; phase: string }
  | { type: "phase_complete"; phase: string }
  | { type: "agent_assigned"; agentId: string; candidate: ExploitCandidate }
  | { type: "agent_skipped"; agentId: string }
  | { type: "agent_done"; agentId: string; result: string }
  | { type: "agent_message"; agentId?: string; text: string }
  | { type: "tool_call"; agentId?: string; tool: string; args: unknown }
  | { type: "tool_result"; agentId?: string; tool: string; result: string }
  | { type: "approval_required"; request: import("./approvalGate.js").ApprovalRequest }
  | { type: "approval_resolved"; id: string; approved: boolean }
  | { type: "scan_complete" }
  | { type: "scan_error"; error: string };

export class ScanOrchestrator extends EventEmitter {
  private scanId: string;
  private gate: ApprovalGate;

  constructor(scanId: string) {
    super();
    this.scanId = scanId;
    this.gate = new ApprovalGate(scanId);

    // Forward gate events to orchestrator listeners
    this.gate.on("approval_required", (req) => {
      this.emit("approval_required", req);
      ScanStore.update(scanId, { status: "awaiting_approval" });
    });
    this.gate.on("approval_resolved", ({ id, approved }) => {
      this.emit("approval_resolved", { id, approved });
      ScanStore.update(scanId, { status: "running" });
    });
  }

  get approvalGate(): ApprovalGate {
    return this.gate;
  }

  async run(targetUrl: string): Promise<void> {
    try {
      registerMcpServer();

      const codex = new Codex();
      const thread = codex.startThread({
        skipGitRepoCheck: true,
        networkAccessEnabled: true,
        sandboxMode: "workspace-write",
      });

      // ── Phase 1: Recon ────────────────────────────────────────────────────
      this.emit("phase_started", { phase: "recon" });
      ScanStore.update(this.scanId, { phase: "recon" });

      const reconOutput = await this.runStreamedTurn(thread, PHASE_PROMPTS.recon(targetUrl));
      const reconJson = extractJson(reconOutput);

      ScanStore.update(this.scanId, { reconResult: reconJson });
      this.emit("phase_complete", { phase: "recon", data: reconJson });

      // Parse exploit candidates
      let reconData: { exploit_candidates?: ExploitCandidate[]; summary?: string } = {};
      try {
        reconData = JSON.parse(reconJson);
      } catch {
        reconData = { exploit_candidates: [], summary: reconOutput };
      }

      const candidates = reconData.exploit_candidates ?? [];

      // ── Human Gate #1: Approve exploit plan ───────────────────────────────
      const planApproved = await this.gate.requestApproval({
        type: "exploit_plan",
        message: `Reconnaissance complete. Found ${candidates.length} potential vulnerabilities to test. Proceed to exploitation?`,
        data: { summary: reconData.summary, candidates },
      });

      if (!planApproved) {
        ScanStore.update(this.scanId, { status: "complete", phase: "complete" });
        this.emit("scan_complete");
        return;
      }

      // ── Phase 2: Exploit ──────────────────────────────────────────────────
      this.emit("phase_started", { phase: "exploit" });
      ScanStore.update(this.scanId, { phase: "exploit" });

      const exploitResults: string[] = [];
      let agentCounter = 1;

      for (const candidate of candidates) {
        const agentId = `AGENT-${String(agentCounter++).padStart(3, "0")}`;

        // Announce agent assignment
        this.emit("agent_assigned", { agentId, candidate });

        // Human Gate #2: Per-exploit approval
        const approved = await this.gate.requestApproval({
          type: "exploit_attempt",
          message: `[${agentId}] Attempt ${candidate.type.toUpperCase()} on ${candidate.endpoint}?`,
          data: { ...candidate, agentId },
        });

        if (!approved) {
          this.emit("agent_skipped", { agentId });
          exploitResults.push(JSON.stringify({ ...candidate, skipped: true }));
          continue;
        }

        // Spawn dedicated agent for this vulnerability
        const agent = new VulnAgent(agentId, candidate);

        // Forward agent events upstream with agentId tagged
        agent.on("agent_message", (data: { agentId: string; text: string }) =>
          this.emit("agent_message", data)
        );
        agent.on("tool_call", (data: { agentId: string; tool: string; args: unknown }) =>
          this.emit("tool_call", data)
        );
        agent.on("tool_result", (data: { agentId: string; tool: string; result: string }) =>
          this.emit("tool_result", data)
        );
        agent.on("agent_done", (data: { agentId: string; result: string }) =>
          this.emit("agent_done", data)
        );

        const exploitOutput = await agent.run();
        const exploitJson = extractJson(exploitOutput);
        exploitResults.push(exploitJson);

        // Add to findings if vulnerable
        try {
          const result = JSON.parse(exploitJson);
          if (result.vulnerable) {
            const normalizedEvidenceSteps = normalizeEvidenceSteps(result, candidate);
            const normalizedReproduction = normalizeReproduction(result, candidate);

            ScanStore.addFinding(this.scanId, {
              id: `VULN-${String(ScanStore.get(this.scanId)!.findings.length + 1).padStart(3, "0")}`,
              type: result.type,
              title: `${result.type.toUpperCase()} on ${candidate.endpoint}`,
              severity: result.severity,
              endpoint: result.endpoint,
              description: candidate.description,
              evidence: result.evidence ?? null,
              evidence_steps: normalizedEvidenceSteps,
              payload: result.payload ?? null,
              reproduction: normalizedReproduction,
              remediation: result.remediation,
            });
            this.emit("finding_discovered", ScanStore.get(this.scanId)!.findings.at(-1));
          }
        } catch {
          // non-JSON output, still save it
        }
      }

      const exploitSummary = exploitResults.join("\n---\n");
      ScanStore.update(this.scanId, { exploitResults: exploitSummary });
      this.emit("phase_complete", { phase: "exploit" });

      // ── Phase 3: Report ───────────────────────────────────────────────────
      this.emit("phase_started", { phase: "report" });
      ScanStore.update(this.scanId, { phase: "report" });

      const reportOutput = await this.runStreamedTurn(
        thread,
        PHASE_PROMPTS.report(reconJson, exploitSummary)
      );
      const reportJson = extractJson(reportOutput);

      ScanStore.update(this.scanId, { report: reportJson, status: "complete", phase: "complete" });
      this.emit("phase_complete", { phase: "report" });
      this.emit("scan_complete");
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      ScanStore.update(this.scanId, { status: "error", error: message });
      this.emit("scan_error", { error: message });
    }
  }

  private async runStreamedTurn(thread: import("@openai/codex-sdk").Thread, prompt: string): Promise<string> {
    const { events } = await thread.runStreamed(prompt);
    let fullText = "";

    for await (const event of events) {
      switch (event.type) {
        case "item.started":
        case "item.updated":
          break;

        case "item.completed":
          if (event.item.type === "agent_message") {
            const text = event.item.text ?? "";
            fullText += text;
            this.emit("agent_message", { text });
          } else if (event.item.type === "mcp_tool_call") {
            this.emit("tool_call", {
              tool: event.item.tool,
              args: event.item.arguments,
            });
            if (event.item.status === "completed" && event.item.result) {
              const resultText =
                event.item.result.content
                  .map((c) => ("text" in c ? c.text : ""))
                  .join("") ?? "";
              this.emit("tool_result", { tool: event.item.tool, result: resultText.slice(0, 500) });
            }
          }
          break;

        case "turn.completed":
          break;

        case "turn.failed":
          throw new Error(`Codex turn failed: ${event.error?.message ?? "unknown"}`);
      }
    }

    return fullText;
  }
}

function extractJson(text: string): string {
  // Try to extract a JSON object from the text
  const match = text.match(/\{[\s\S]*\}/);
  if (match) return match[0];
  return text;
}

function normalizeEvidenceSteps(
  result: Record<string, unknown>,
  candidate: ExploitCandidate
): string[] {
  if (Array.isArray(result.evidence_steps) && result.evidence_steps.length > 0) {
    return result.evidence_steps.map((step, i) => {
      const s = String(step ?? "").trim();
      if (!s) return `Step ${i + 1}: (no detail provided)`;
      return /^step\s*\d+:/i.test(s) ? s : `Step ${i + 1}: ${s}`;
    });
  }

  const payload =
    typeof result.payload === "string" && result.payload.trim().length > 0
      ? result.payload.trim()
      : "<payload not provided>";
  const evidence =
    typeof result.evidence === "string" && result.evidence.trim().length > 0
      ? result.evidence.trim()
      : "No exact response details were returned by the model.";

  return [
    `Step 1: Prepare request — Send a ${candidate.method} request to ${candidate.endpoint} and note the baseline response for parameter ${candidate.param}.`,
    `Step 2: Attack input — Send ${candidate.param}=${payload} and keep all other request fields unchanged.`,
    `Step 3: Observe output — ${evidence}`,
    `Step 4: Why this matters — the changed response shows untrusted input is affecting security-sensitive behavior (${candidate.type.toUpperCase()}).`,
  ];
}

function normalizeReproduction(
  result: Record<string, unknown>,
  candidate: ExploitCandidate
): string {
  if (typeof result.reproduction === "string" && result.reproduction.trim().length > 0) {
    return result.reproduction.trim();
  }

  const payload =
    typeof result.payload === "string" && result.payload.trim().length > 0
      ? result.payload.trim()
      : "test";
  const encodedPayload = encodeURIComponent(payload);

  if (candidate.method.toUpperCase() === "POST") {
    return `curl -s -X POST '${candidate.endpoint}' -H 'Content-Type: application/x-www-form-urlencoded' --data '${candidate.param}=${encodedPayload}'`;
  }

  const separator = candidate.endpoint.includes("?") ? "&" : "?";
  return `curl -s '${candidate.endpoint}${separator}${candidate.param}=${encodedPayload}'`;
}
