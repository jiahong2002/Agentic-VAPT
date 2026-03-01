import type { ReactNode } from "react";
import type { ApprovalRequest } from "../hooks/useWebSocket";

interface Props {
  request: ApprovalRequest | null;
  onApprove: () => void;
  onDeny: () => void;
}

interface ExploitCandidate {
  type: string; endpoint: string; param: string;
  method: string; description: string; priority: string;
}
interface ExploitPlanData {
  summary?: string;
  candidates?: ExploitCandidate[];
}

const TYPE_COLORS: Record<string, string> = {
  sqli: "#dc2626", xss: "#7c3aed", file_exposure: "#0891b2", header: "#0d9488",
};

export function ApprovalModal({ request, onApprove, onDeny }: Props) {
  if (!request) return null;

  const isExploitPlan = request.requestType === "exploit_plan";
  const planData = isExploitPlan ? (request.data as ExploitPlanData) : null;
  const candidate = !isExploitPlan ? (request.data as ExploitCandidate) : null;

  return (
    <div style={{
      position: "fixed", inset: 0, zIndex: 1000,
      background: "rgba(0,0,0,0.75)",
      backdropFilter: "blur(4px)",
      display: "flex", alignItems: "center", justifyContent: "center", padding: "1rem",
    }}>
      <div style={{
        background: "var(--card)",
        border: "1px solid var(--border-light)",
        borderRadius: 16,
        padding: "1.75rem",
        maxWidth: 580, width: "100%",
        boxShadow: "0 0 60px rgba(239,68,68,0.15), 0 25px 50px rgba(0,0,0,0.5)",
        animation: "modal-in 0.25s ease",
      }}>
        {/* Header */}
        <div style={{ display: "flex", alignItems: "center", gap: 12, marginBottom: "1.25rem" }}>
          <div style={{
            width: 44, height: 44, borderRadius: 12,
            background: "rgba(239,68,68,0.15)",
            border: "1px solid rgba(239,68,68,0.3)",
            display: "flex", alignItems: "center", justifyContent: "center",
            fontSize: "1.3rem", flexShrink: 0,
            animation: "pulse-glow 2s ease-in-out infinite",
          }}>⚠️</div>
          <div>
            <div style={{ fontWeight: 700, fontSize: "1rem", color: "var(--text-primary)" }}>
              Human Authorization Required
            </div>
            <div style={{ color: "var(--text-secondary)", fontSize: "0.8rem", marginTop: 2 }}>
              The AI agent requires your approval to continue
            </div>
          </div>
          {/* Pulsing dot */}
          <div style={{ marginLeft: "auto", display: "flex", alignItems: "center", gap: 6 }}>
            <div style={{ width: 8, height: 8, borderRadius: "50%", background: "#ef4444", animation: "blink 1s ease infinite" }} />
            <span style={{ fontSize: "0.72rem", color: "#ef4444", fontWeight: 600 }}>AWAITING</span>
          </div>
        </div>

        {/* Message */}
        <p style={{ color: "var(--text-secondary)", marginBottom: "1.2rem", lineHeight: 1.6, fontSize: "0.9rem" }}>
          {request.message}
        </p>

        {/* Exploit plan view */}
        {isExploitPlan && planData && (
          <div style={{ background: "var(--surface)", border: "1px solid var(--border)", borderRadius: 10, padding: "1rem", marginBottom: "1.25rem" }}>
            {planData.summary && (
              <p style={{ color: "var(--text-secondary)", fontSize: "0.83rem", marginBottom: "0.8rem", lineHeight: 1.6 }}>
                {planData.summary}
              </p>
            )}
            {planData.candidates && planData.candidates.length > 0 && (
              <div>
                <div style={{ fontSize: "0.72rem", fontWeight: 600, color: "var(--text-dim)", textTransform: "uppercase", letterSpacing: "0.07em", marginBottom: 8 }}>
                  {planData.candidates.length} tests queued
                </div>
                <div style={{ maxHeight: 200, overflowY: "auto", display: "flex", flexDirection: "column", gap: 4 }}>
                  {planData.candidates.map((c, i) => (
                    <div key={i} style={{
                      display: "flex", alignItems: "center", gap: 8,
                      padding: "5px 8px",
                      background: "rgba(255,255,255,0.03)",
                      borderRadius: 6, fontSize: "0.8rem",
                    }}>
                      <span style={{
                        background: TYPE_COLORS[c.type] ?? "#64748b",
                        color: "white", padding: "1px 7px", borderRadius: 4,
                        fontSize: "0.68rem", fontWeight: 700, minWidth: 52, textAlign: "center",
                      }}>{c.type.toUpperCase()}</span>
                      <span style={{ color: "var(--text-secondary)", fontFamily: "var(--mono)", fontSize: "0.78rem", wordBreak: "break-all" }}>
                        {c.endpoint}{c.param ? `?${c.param}` : ""}
                      </span>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        )}

        {/* Single exploit detail */}
        {!isExploitPlan && candidate && (
          <div style={{
            background: "rgba(220,38,38,0.06)", border: "1px solid rgba(220,38,38,0.2)",
            borderRadius: 10, padding: "1rem", marginBottom: "1.25rem",
            borderLeft: "3px solid #dc2626",
          }}>
            <div style={{ display: "grid", gridTemplateColumns: "90px 1fr", gap: "6px 12px", fontSize: "0.82rem" }}>
              {[
                ["Attack Type", <span style={{ fontWeight: 700, color: TYPE_COLORS[candidate.type] ?? "var(--text-primary)" }}>{candidate.type?.toUpperCase()}</span>],
                ["Method", candidate.method],
                ["Endpoint", <code style={{ fontFamily: "var(--mono)", fontSize: "0.78rem", wordBreak: "break-all", color: "#93c5fd" }}>{candidate.endpoint}</code>],
                ["Parameter", <code style={{ fontFamily: "var(--mono)", fontSize: "0.78rem", color: "#86efac" }}>{candidate.param || "—"}</code>],
                ["Reason", <span style={{ color: "var(--text-secondary)", lineHeight: 1.5 }}>{candidate.description}</span>],
              ].map(([label, value], i) => (
                <>
                  <span key={`l${i}`} style={{ color: "var(--text-dim)", fontWeight: 500 }}>{label as string}</span>
                  <span key={`v${i}`}>{value as ReactNode}</span>
                </>
              ))}
            </div>
          </div>
        )}

        {/* Action buttons */}
        <div style={{ display: "flex", gap: 10, justifyContent: "flex-end" }}>
          <button onClick={onDeny} style={{
            padding: "0.65rem 1.4rem",
            background: "transparent",
            border: "1px solid var(--border-light)",
            color: "var(--text-secondary)",
            borderRadius: 8, fontWeight: 600, cursor: "pointer",
            fontSize: "0.875rem", fontFamily: "var(--font)",
            transition: "all 0.15s",
          }}
            onMouseEnter={(e) => { (e.target as HTMLButtonElement).style.borderColor = "var(--text-secondary)"; (e.target as HTMLButtonElement).style.color = "var(--text-primary)"; }}
            onMouseLeave={(e) => { (e.target as HTMLButtonElement).style.borderColor = "var(--border-light)"; (e.target as HTMLButtonElement).style.color = "var(--text-secondary)"; }}
          >
            Deny / Skip
          </button>
          <button onClick={onApprove} style={{
            padding: "0.65rem 1.4rem",
            background: "#dc2626",
            border: "none", color: "white",
            borderRadius: 8, fontWeight: 700, cursor: "pointer",
            fontSize: "0.875rem", fontFamily: "var(--font)",
            boxShadow: "0 4px 14px rgba(220,38,38,0.4)",
            transition: "all 0.15s",
          }}
            onMouseEnter={(e) => { (e.target as HTMLButtonElement).style.transform = "translateY(-1px)"; (e.target as HTMLButtonElement).style.boxShadow = "0 6px 20px rgba(220,38,38,0.5)"; }}
            onMouseLeave={(e) => { (e.target as HTMLButtonElement).style.transform = "none"; (e.target as HTMLButtonElement).style.boxShadow = "0 4px 14px rgba(220,38,38,0.4)"; }}
          >
            Approve ⚡
          </button>
        </div>
      </div>
    </div>
  );
}
