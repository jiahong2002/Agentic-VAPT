import { useEffect, useRef, useState, useCallback } from "react";

export interface ApprovalRequest {
  approvalId: string;
  scanId: string;
  requestType: "exploit_plan" | "exploit_attempt";
  message: string;
  data: unknown;
}

export interface Finding {
  id: string;
  type: string;
  title: string;
  severity: "critical" | "high" | "medium" | "low";
  endpoint: string;
  description: string;
  evidence: string | null;
  evidence_steps: string[] | null;
  payload: string | null;
  reproduction: string | null;
  remediation: string;
}

export interface LogEntry {
  time: string;
  type: string;
  text: string;
  severity?: string;
  agentId?: string;
}

export interface AgentInfo {
  agentId: string;
  candidateType: string;
  endpoint: string;
  param: string;
  status: "spawned" | "running" | "done" | "skipped";
}

export type ScanPhase = "idle" | "recon" | "exploit" | "report" | "complete" | "error";

export function useWebSocket(scanId: string | null) {
  const [phase, setPhase] = useState<ScanPhase>("idle");
  const [log, setLog] = useState<LogEntry[]>([]);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [agents, setAgents] = useState<AgentInfo[]>([]);
  const [pendingApproval, setPendingApproval] = useState<ApprovalRequest | null>(null);
  const [isComplete, setIsComplete] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const wsRef = useRef<WebSocket | null>(null);
  const reconnectTimer = useRef<ReturnType<typeof setTimeout> | null>(null);
  const reconnectCount = useRef(0);
  const unmounted = useRef(false);
  const hasLoggedInitialConnect = useRef(false);
  const recentEventKeys = useRef<Map<string, number>>(new Map());

  const addLog = useCallback((type: string, text: string, severity?: string, agentId?: string) => {
    setLog((prev) => [
      ...prev,
      { time: new Date().toLocaleTimeString(), type, text, severity, agentId },
    ]);
  }, []);

  const updateAgent = useCallback((agentId: string, status: AgentInfo["status"]) => {
    setAgents((prev) =>
      prev.map((a) => (a.agentId === agentId ? { ...a, status } : a))
    );
  }, []);

  useEffect(() => {
    if (!scanId) return;
    unmounted.current = false;
    const wsProtocol = window.location.protocol === "https:" ? "wss:" : "ws:";
    hasLoggedInitialConnect.current = false;

    // Fetch latest persisted scan status so the UI reflects real state after refresh/reconnect.
    fetch(`/api/scan/${scanId}/status`)
      .then((r) => (r.ok ? r.json() : null))
      .then((status) => {
        if (!status || unmounted.current) return;
        if (status.phase) setPhase(status.phase as ScanPhase);
        if (Array.isArray(status.findings)) setFindings(status.findings as Finding[]);
        if (status.status === "complete") setIsComplete(true);
        if (status.error) setError(String(status.error));
      })
      .catch(() => {
        // Ignore transient status fetch failures; websocket stream still provides live updates.
      });

    function connect() {
      if (unmounted.current) return;
      if (wsRef.current && (wsRef.current.readyState === WebSocket.OPEN || wsRef.current.readyState === WebSocket.CONNECTING)) {
        return;
      }
      const ws = new WebSocket(`${wsProtocol}//${window.location.host}/ws?scanId=${scanId}`);
      wsRef.current = ws;

      ws.onopen = () => {
        if (reconnectTimer.current) {
          clearTimeout(reconnectTimer.current);
          reconnectTimer.current = null;
        }
        const wasReconnect = reconnectCount.current > 0;
        reconnectCount.current = 0;
        if (!hasLoggedInitialConnect.current) {
          hasLoggedInitialConnect.current = true;
          addLog("system", "Connected to scan stream");
        } else if (wasReconnect) {
          addLog("system", "Reconnected to scan stream");
        }
      };

      ws.onmessage = (evt) => {
        let msg: Record<string, unknown>;
        try {
          msg = JSON.parse(evt.data as string);
        } catch {
          return;
        }

        // Deduplicate repeated websocket events (can happen in dev with duplicate subscriptions).
        const eventKey = JSON.stringify(msg);
        const now = Date.now();
        const prevTs = recentEventKeys.current.get(eventKey);
        if (prevTs && now - prevTs < 1500) return;
        recentEventKeys.current.set(eventKey, now);
        if (recentEventKeys.current.size > 400) {
          for (const [k, ts] of recentEventKeys.current) {
            if (now - ts > 5000) recentEventKeys.current.delete(k);
          }
        }

        switch (msg.type) {
          case "scan.started":
            addLog("system", `Scan started on ${msg.url}`);
            break;
          case "phase.started":
            setPhase(msg.phase as ScanPhase);
            addLog("phase", `Phase started: ${String(msg.phase).toUpperCase()}`);
            break;
          case "phase.complete":
            addLog("phase", `Phase complete: ${String(msg.phase).toUpperCase()}`);
            break;
          case "agent.assigned": {
            const info: AgentInfo = {
              agentId: msg.agentId as string,
              candidateType: msg.candidateType as string,
              endpoint: msg.endpoint as string,
              param: msg.param as string,
              status: "spawned",
            };
            setAgents((prev) => (prev.some((a) => a.agentId === info.agentId) ? prev : [...prev, info]));
            addLog(
              "agent_assign",
              `${msg.agentId} assigned → ${String(msg.candidateType).toUpperCase()} on ${msg.endpoint}`,
              undefined,
              msg.agentId as string
            );
            break;
          }
          case "agent.skipped":
            updateAgent(msg.agentId as string, "skipped");
            addLog("agent_assign", `${msg.agentId} skipped (denied)`, undefined, msg.agentId as string);
            break;
          case "agent.done":
            updateAgent(msg.agentId as string, "done");
            addLog("agent_assign", `${msg.agentId} completed`, undefined, msg.agentId as string);
            break;
          case "agent.message": {
            const agentId = msg.agentId as string | undefined;
            if (agentId) updateAgent(agentId, "running");
            addLog("agent", String(msg.text ?? "").slice(0, 300), undefined, agentId);
            break;
          }
          case "tool.called": {
            const agentId = msg.agentId as string | undefined;
            addLog("tool", `Calling tool: ${msg.tool}`, "info", agentId);
            break;
          }
          case "tool.result": {
            const agentId = msg.agentId as string | undefined;
            addLog(
              "tool",
              `Result from ${msg.tool}: ${String(msg.result ?? "").slice(0, 200)}`,
              "success",
              agentId
            );
            break;
          }
          case "finding.discovered": {
            const f = msg.finding as Finding;
            setFindings((prev) => (prev.some((existing) => existing.id === f.id) ? prev : [...prev, f]));
            addLog("finding", `Found: ${f.title}`, f.severity);
            break;
          }
          case "approval.required":
            setPendingApproval({
              approvalId: msg.approvalId as string,
              scanId: msg.scanId as string,
              requestType: msg.requestType as "exploit_plan" | "exploit_attempt",
              message: msg.message as string,
              data: msg.data,
            });
            addLog("approval", `Awaiting human approval: ${msg.message}`);
            break;
          case "approval.resolved":
            setPendingApproval(null);
            addLog("approval", `Approval ${msg.approved ? "granted" : "denied"}`);
            break;
          case "scan.complete":
            setPhase("complete");
            setIsComplete(true);
            addLog("system", "Scan complete! Report is ready.");
            break;
          case "scan.error":
            setPhase("error");
            setError(String(msg.error));
            addLog("error", `Error: ${msg.error}`);
            break;
        }
      };

      ws.onclose = () => {
        if (unmounted.current) return;
        if (wsRef.current !== ws) return;
        // Silent auto-reconnect — back-off up to 5s
        const delay = Math.min(1000 * 2 ** reconnectCount.current, 5000);
        reconnectCount.current += 1;
        reconnectTimer.current = setTimeout(connect, delay);
      };

      // Suppress transient onerror noise — onclose will handle reconnect
      ws.onerror = () => { /* intentionally silent */ };
    }

    connect();

    return () => {
      unmounted.current = true;
      if (reconnectTimer.current) clearTimeout(reconnectTimer.current);
      wsRef.current?.close();
      wsRef.current = null;
    };
  }, [scanId, addLog, updateAgent]);

  const submitApproval = useCallback(
    async (approvalId: string, approved: boolean) => {
      if (!scanId) return;
      await fetch(`/api/approve/${scanId}`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ approvalId, approved }),
      });
      setPendingApproval(null);
    },
    [scanId]
  );

  return { phase, log, findings, agents, pendingApproval, isComplete, error, submitApproval };
}
