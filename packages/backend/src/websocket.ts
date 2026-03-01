import { WebSocketServer, WebSocket } from "ws";
import type { IncomingMessage, Server } from "http";

export type WSMessage =
  | { type: "scan.started"; scanId: string; url: string }
  | { type: "phase.started"; phase: string }
  | { type: "phase.complete"; phase: string; data?: unknown }
  | { type: "agent.assigned"; agentId: string; candidateType: string; endpoint: string; param: string }
  | { type: "agent.skipped"; agentId: string }
  | { type: "agent.done"; agentId: string }
  | { type: "agent.message"; agentId?: string; text: string }
  | { type: "tool.called"; agentId?: string; tool: string; args: unknown }
  | { type: "tool.result"; agentId?: string; tool: string; result: string }
  | { type: "finding.discovered"; finding: unknown }
  | { type: "approval.required"; approvalId: string; scanId: string; requestType: string; message: string; data: unknown }
  | { type: "approval.resolved"; approvalId: string; approved: boolean }
  | { type: "scan.complete" }
  | { type: "scan.error"; error: string };

export class WSManager {
  private wss: WebSocketServer;
  // scanId → set of connected WebSocket clients
  private clients = new Map<string, Set<WebSocket>>();

  constructor(server: Server) {
    this.wss = new WebSocketServer({ server, path: "/ws" });

    this.wss.on("connection", (ws: WebSocket, req: IncomingMessage) => {
      const searchParams = new URL(req.url ?? "/", "ws://localhost").searchParams;
      const scanId = searchParams.get("scanId");

      if (!scanId) {
        ws.close(1008, "scanId required");
        return;
      }

      if (!this.clients.has(scanId)) this.clients.set(scanId, new Set());
      this.clients.get(scanId)!.add(ws);

      ws.on("close", () => {
        this.clients.get(scanId)?.delete(ws);
      });

      ws.on("error", () => {
        this.clients.get(scanId)?.delete(ws);
      });
    });
  }

  broadcast(scanId: string, message: WSMessage): void {
    const scanClients = this.clients.get(scanId);
    if (!scanClients?.size) return;
    const payload = JSON.stringify(message);
    for (const client of scanClients) {
      if (client.readyState === WebSocket.OPEN) {
        client.send(payload);
      }
    }
  }
}
