import { useParams, useNavigate } from "react-router-dom";
import { useWebSocket } from "../hooks/useWebSocket";
import { PhaseTracker } from "../components/PhaseTracker";
import { LiveFeed } from "../components/LiveFeed";
import { ApprovalModal } from "../components/ApprovalModal";
import { FindingCard } from "../components/FindingCard";
import { AgentPool } from "../components/AgentPool";

const SEV_ORDER = ["critical", "high", "medium", "low"] as const;
type StepState = "done" | "active" | "waiting";

const PENTEST_STEPS = [
  {
    id: 1,
    title: "Reconnaissance",
    details:
      "The agent crawls pages, checks security headers, and probes common exposed files to map attack surface.",
  },
  {
    id: 2,
    title: "Exploit Plan Approval",
    details:
      "You review all potential attack candidates. Exploitation does not begin until you approve the plan.",
  },
  {
    id: 3,
    title: "Controlled Exploitation",
    details:
      "Agents test SQLi/XSS/file issues one by one. Each exploit attempt can require your explicit approval.",
  },
  {
    id: 4,
    title: "Evidence Collection",
    details:
      "For each confirmed vulnerability, the system saves payload, exact server behavior, and reproducible commands.",
  },
  {
    id: 5,
    title: "Report Generation",
    details:
      "Findings are prioritized by severity with remediation guidance and proof-of-concept details.",
  },
] as const;

export function ScanPage() {
  const { scanId } = useParams<{ scanId: string }>();
  const navigate = useNavigate();
  const { phase, log, findings, agents, pendingApproval, isComplete, error, submitApproval } =
    useWebSocket(scanId ?? null);

  const handleApprove = () => { if (pendingApproval) submitApproval(pendingApproval.approvalId, true); };
  const handleDeny   = () => { if (pendingApproval) submitApproval(pendingApproval.approvalId, false); };

  const counts = SEV_ORDER.reduce((acc, s) => {
    acc[s] = findings.filter((f) => f.severity === s).length;
    return acc;
  }, {} as Record<string, number>);

  const getPentestStepState = (stepId: number): StepState => {
    if (isComplete) return "done";
    if (error) return "waiting";

    if (stepId === 1) {
      return phase === "idle" ? "waiting" : phase === "recon" ? "active" : "done";
    }

    if (stepId === 2) {
      if (phase === "idle" || phase === "recon") return "waiting";
      if (pendingApproval?.requestType === "exploit_plan") return "active";
      return phase === "exploit" || phase === "report" || phase === "complete" ? "done" : "waiting";
    }

    if (stepId === 3) {
      if (phase === "exploit") return "active";
      return phase === "report" || phase === "complete" ? "done" : "waiting";
    }

    if (stepId === 4) {
      if (phase === "report") return "done";
      if (phase === "exploit") return findings.length > 0 ? "active" : "waiting";
      return phase === "complete" ? "done" : "waiting";
    }

    // stepId === 5
    if (phase === "report") return "active";
    if (phase === "complete") return "done";
    return "waiting";
  };

  const statusStyle = (state: StepState): { label: string; color: string; bg: string; border: string } => {
    if (state === "done") {
      return { label: "DONE", color: "#22c55e", bg: "rgba(34,197,94,0.12)", border: "rgba(34,197,94,0.35)" };
    }
    if (state === "active") {
      return { label: "ACTIVE", color: "#3b82f6", bg: "rgba(59,130,246,0.12)", border: "rgba(59,130,246,0.35)" };
    }
    return { label: "WAITING", color: "#94a3b8", bg: "rgba(148,163,184,0.12)", border: "rgba(148,163,184,0.3)" };
  };

  return (
    <div style={{ minHeight: "100vh", background: "var(--bg)", fontFamily: "var(--font)" }}>
      <ApprovalModal request={pendingApproval} onApprove={handleApprove} onDeny={handleDeny} />

      {/* Top nav */}
      <nav style={{
        background: "var(--surface)",
        borderBottom: "1px solid var(--border)",
        padding: "0 1.5rem",
        height: 56,
        display: "flex", alignItems: "center", justifyContent: "space-between",
        position: "sticky", top: 0, zIndex: 100,
        backdropFilter: "blur(12px)",
      }}>
        <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
          <button onClick={() => navigate("/")} style={{
            background: "none", border: "none", color: "var(--text-dim)",
            cursor: "pointer", fontSize: "0.85rem", padding: "4px 8px",
            borderRadius: 6, fontFamily: "var(--font)",
            display: "flex", alignItems: "center", gap: 5,
          }}>
            ← Back
          </button>
          <div style={{ width: 1, height: 20, background: "var(--border)" }} />
          <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
            <div style={{
              width: 28, height: 28, borderRadius: 7,
              background: "#3b82f6",
              display: "flex", alignItems: "center", justifyContent: "center", fontSize: "0.9rem",
            }}>🔐</div>
            <span style={{ fontWeight: 700, fontSize: "0.95rem" }}>AgenticVAPT</span>
          </div>
          <div style={{ width: 1, height: 20, background: "var(--border)" }} />
          <span style={{ color: "var(--text-dim)", fontSize: "0.78rem", fontFamily: "var(--mono)" }}>
            {scanId?.slice(0, 8)}...
          </span>
        </div>

        <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
          {/* Phase badge */}
          {phase !== "idle" && phase !== "complete" && phase !== "error" && (
            <div style={{
              background: "rgba(59,130,246,0.1)", border: "1px solid rgba(59,130,246,0.25)",
              borderRadius: 6, padding: "3px 10px",
              display: "flex", alignItems: "center", gap: 5,
            }}>
              <div style={{ width: 6, height: 6, borderRadius: "50%", background: "var(--primary)", animation: "blink 1.2s ease infinite" }} />
              <span style={{ fontSize: "0.75rem", color: "var(--primary)", fontWeight: 600, textTransform: "uppercase" }}>
                {phase}
              </span>
            </div>
          )}

          {pendingApproval && (
            <div style={{
              background: "rgba(239,68,68,0.1)", border: "1px solid rgba(239,68,68,0.3)",
              borderRadius: 6, padding: "3px 10px",
              display: "flex", alignItems: "center", gap: 5,
            }}>
              <div style={{ width: 6, height: 6, borderRadius: "50%", background: "#ef4444", animation: "blink 0.8s ease infinite" }} />
              <span style={{ fontSize: "0.75rem", color: "#ef4444", fontWeight: 600 }}>AWAITING APPROVAL</span>
            </div>
          )}

          {isComplete && (
            <a
              href={`/api/report/${scanId}`}
              target="_blank"
              rel="noreferrer"
              style={{
                background: "#16a34a",
                color: "white", padding: "5px 14px", borderRadius: 8,
                fontWeight: 700, textDecoration: "none", fontSize: "0.82rem",
                display: "flex", alignItems: "center", gap: 5,
                boxShadow: "0 4px 12px rgba(34,197,94,0.3)",
              }}
            >
              📄 View Full Report
            </a>
          )}

          <button onClick={() => navigate("/")} style={{
            background: "var(--card)", border: "1px solid var(--border)",
            color: "var(--text-secondary)", padding: "5px 14px", borderRadius: 8,
            cursor: "pointer", fontSize: "0.82rem", fontWeight: 600, fontFamily: "var(--font)",
          }}>
            + New Scan
          </button>
        </div>
      </nav>

      <div style={{ padding: "1.5rem", maxWidth: 1280, margin: "0 auto" }}>

        {/* Severity summary row */}
        <div style={{ display: "grid", gridTemplateColumns: "repeat(4, 1fr)", gap: "0.75rem", marginBottom: "1.25rem" }}>
          {([
            { sev: "critical", color: "#dc2626", bg: "rgba(220,38,38,0.08)", border: "rgba(220,38,38,0.2)", label: "Critical" },
            { sev: "high",     color: "#ea580c", bg: "rgba(234,88,12,0.08)",  border: "rgba(234,88,12,0.2)",  label: "High" },
            { sev: "medium",   color: "#d97706", bg: "rgba(217,119,6,0.08)",  border: "rgba(217,119,6,0.2)",  label: "Medium" },
            { sev: "low",      color: "#65a30d", bg: "rgba(101,163,13,0.08)", border: "rgba(101,163,13,0.2)", label: "Low" },
          ] as const).map(({ sev, color, bg, border, label }) => (
            <div key={sev} style={{
              background: bg, border: `1px solid ${border}`, borderRadius: 10, padding: "0.9rem 1.1rem",
              animation: "fade-in 0.4s ease both",
            }}>
              <div style={{ fontSize: "1.6rem", fontWeight: 800, color, fontFamily: "var(--mono)" }}>
                {counts[sev] ?? 0}
              </div>
              <div style={{ fontSize: "0.75rem", color, fontWeight: 600, textTransform: "uppercase", letterSpacing: "0.06em", marginTop: 2 }}>
                {label}
              </div>
            </div>
          ))}
        </div>

        {/* Phase tracker */}
        <div style={{
          background: "var(--card)", border: "1px solid var(--border)",
          borderRadius: 12, padding: "1.25rem", marginBottom: "1.25rem",
        }}>
          <div style={{ fontSize: "0.72rem", fontWeight: 600, color: "var(--text-dim)", textTransform: "uppercase", letterSpacing: "0.08em", marginBottom: "1rem" }}>
            Pipeline Status
          </div>
          <PhaseTracker currentPhase={phase} />

          {/* Status banners */}
          {isComplete && (
            <div style={{
              marginTop: "1rem", background: "rgba(34,197,94,0.08)",
              border: "1px solid rgba(34,197,94,0.25)", borderRadius: 8,
              padding: "0.7rem 1rem", color: "var(--success)", fontWeight: 600, fontSize: "0.875rem",
              display: "flex", alignItems: "center", gap: 8,
            }}>
              <span>✅</span>
              Scan complete — {findings.length} finding{findings.length !== 1 ? "s" : ""} discovered.
              <a href={`/api/report/${scanId}`} target="_blank" rel="noreferrer"
                style={{ marginLeft: "auto", color: "var(--success)", fontSize: "0.82rem", fontWeight: 700 }}>
                Open Report →
              </a>
            </div>
          )}
          {error && (
            <div style={{
              marginTop: "1rem", background: "rgba(239,68,68,0.08)",
              border: "1px solid rgba(239,68,68,0.25)", borderRadius: 8,
              padding: "0.7rem 1rem", color: "#fca5a5", fontSize: "0.875rem",
            }}>
              ❌ Error: {error}
            </div>
          )}
          {pendingApproval && (
            <div style={{
              marginTop: "1rem", background: "rgba(239,68,68,0.06)",
              border: "1px solid rgba(239,68,68,0.2)", borderRadius: 8,
              padding: "0.7rem 1rem", color: "#fca5a5", fontWeight: 600, fontSize: "0.875rem",
              display: "flex", alignItems: "center", gap: 8,
              animation: "pulse-glow 2s ease infinite",
            }}>
              <div style={{ width: 8, height: 8, borderRadius: "50%", background: "#ef4444", animation: "blink 0.8s ease infinite" }} />
              Scan paused — awaiting your approval in the popup
            </div>
          )}
        </div>

        {/* User-facing pentest workflow */}
        <div style={{
          background: "var(--card)", border: "1px solid var(--border)",
          borderRadius: 12, padding: "1.25rem", marginBottom: "1.25rem",
        }}>
          <div style={{ fontSize: "0.72rem", fontWeight: 600, color: "var(--text-dim)", textTransform: "uppercase", letterSpacing: "0.08em", marginBottom: "0.9rem" }}>
            How This Pentest Works
          </div>

          <div style={{ display: "flex", flexDirection: "column", gap: "0.65rem" }}>
            {PENTEST_STEPS.map((step) => {
              const state = getPentestStepState(step.id);
              const badge = statusStyle(state);
              return (
                <div key={step.id} style={{
                  border: `1px solid ${badge.border}`,
                  background: badge.bg,
                  borderRadius: 10,
                  padding: "0.75rem 0.85rem",
                  display: "flex",
                  gap: 10,
                  alignItems: "flex-start",
                }}>
                  <div style={{
                    flexShrink: 0,
                    width: 22,
                    height: 22,
                    borderRadius: "50%",
                    border: `1px solid ${badge.border}`,
                    color: badge.color,
                    fontSize: "0.72rem",
                    fontWeight: 700,
                    display: "flex",
                    alignItems: "center",
                    justifyContent: "center",
                    marginTop: 1,
                  }}>
                    {step.id}
                  </div>

                  <div style={{ flex: 1, minWidth: 0 }}>
                    <div style={{ display: "flex", alignItems: "center", gap: 8, flexWrap: "wrap", marginBottom: 4 }}>
                      <span style={{ fontWeight: 700, fontSize: "0.82rem", color: "var(--text-primary)" }}>
                        {step.title}
                      </span>
                      <span style={{
                        fontSize: "0.62rem",
                        fontWeight: 700,
                        letterSpacing: "0.08em",
                        padding: "2px 7px",
                        borderRadius: 999,
                        border: `1px solid ${badge.border}`,
                        color: badge.color,
                        background: "rgba(15,23,42,0.3)",
                      }}>
                        {badge.label}
                      </span>
                    </div>
                    <div style={{ fontSize: "0.75rem", color: "#cbd5e1", lineHeight: 1.45 }}>
                      {step.details}
                    </div>
                  </div>
                </div>
              );
            })}
          </div>
        </div>

        {/* Agent Pool */}
        <AgentPool agents={agents} />

        {/* Main 2-col layout */}
        <div style={{ display: "grid", gridTemplateColumns: "1fr 300px", gap: "1.25rem" }}>

          {/* Live feed */}
          <div style={{ background: "var(--card)", border: "1px solid var(--border)", borderRadius: 12, padding: "1.25rem" }}>
            <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: "1rem" }}>
              <div style={{ fontSize: "0.72rem", fontWeight: 600, color: "var(--text-dim)", textTransform: "uppercase", letterSpacing: "0.08em" }}>
                Live Agent Feed
              </div>
              {log.length > 0 && phase !== "complete" && phase !== "error" && (
                <div style={{ display: "flex", alignItems: "center", gap: 4, marginLeft: "auto" }}>
                  <div style={{ width: 5, height: 5, borderRadius: "50%", background: "var(--success)", animation: "blink 1.5s ease infinite" }} />
                  <span style={{ fontSize: "0.7rem", color: "var(--success)" }}>LIVE</span>
                </div>
              )}
            </div>
            <LiveFeed log={log} />
          </div>

          {/* Findings panel */}
          <div style={{ background: "var(--card)", border: "1px solid var(--border)", borderRadius: 12, padding: "1.25rem" }}>
            <div style={{ fontSize: "0.72rem", fontWeight: 600, color: "var(--text-dim)", textTransform: "uppercase", letterSpacing: "0.08em", marginBottom: "1rem", display: "flex", justifyContent: "space-between" }}>
              <span>Findings</span>
              {findings.length > 0 && <span style={{ color: "var(--primary)" }}>{findings.length}</span>}
            </div>

            <div style={{ maxHeight: 380, overflowY: "auto" }}>
              {findings.length === 0 ? (
                <div style={{ textAlign: "center", paddingTop: "3rem", color: "var(--text-dim)" }}>
                  <div style={{ fontSize: "2rem", marginBottom: 8, opacity: 0.4 }}>🔒</div>
                  <div style={{ fontSize: "0.8rem" }}>No findings yet</div>
                </div>
              ) : (
                findings.map((f, i) => <FindingCard key={f.id} finding={f} index={i} />)
              )}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
