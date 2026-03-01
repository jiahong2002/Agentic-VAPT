import type { ScanPhase } from "../hooks/useWebSocket";

const PHASES: { key: ScanPhase; label: string; icon: string; desc: string }[] = [
  { key: "recon", label: "Reconnaissance", icon: "🔍", desc: "Crawl · Headers · Files" },
  { key: "exploit", label: "Exploitation", icon: "⚡", desc: "SQLi · XSS · Probing" },
  { key: "report", label: "Report", icon: "📊", desc: "Analysis · Remediation" },
];

interface Props {
  currentPhase: ScanPhase;
}

export function PhaseTracker({ currentPhase }: Props) {
  const order: ScanPhase[] = ["idle", "recon", "exploit", "report", "complete"];
  const currentIdx = order.indexOf(currentPhase === "error" ? "idle" : currentPhase);

  const getStatus = (key: ScanPhase): "done" | "active" | "pending" => {
    if (currentPhase === "complete") return "done";
    const keyIdx = order.indexOf(key);
    if (keyIdx < currentIdx) return "done";
    if (keyIdx === currentIdx) return "active";
    return "pending";
  };

  return (
    <div style={{ display: "flex", alignItems: "stretch", gap: 0 }}>
      {PHASES.map((phase, i) => {
        const status = getStatus(phase.key);
        return (
          <div key={phase.key} style={{ display: "flex", alignItems: "center", flex: 1 }}>
            <div style={{
              flex: 1,
              background: status === "done" ? "rgba(34,197,94,0.08)" : status === "active" ? "rgba(59,130,246,0.08)" : "transparent",
              border: `1px solid ${status === "done" ? "rgba(34,197,94,0.25)" : status === "active" ? "rgba(59,130,246,0.35)" : "var(--border)"}`,
              borderRadius: 10, padding: "1rem", transition: "all 0.4s ease",
              position: "relative", overflow: "hidden",
            }}>
              {status === "active" && (
                <div style={{
                  position: "absolute", top: 0, left: 0, right: 0, height: 2,
                  background: "var(--primary)",
                  animation: "scan-line 2s linear infinite",
                }} />
              )}
              <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
                <div style={{
                  width: 36, height: 36, borderRadius: "50%", flexShrink: 0,
                  display: "flex", alignItems: "center", justifyContent: "center",
                  background: status === "done" ? "rgba(34,197,94,0.2)" : status === "active" ? "rgba(59,130,246,0.2)" : "var(--surface)",
                  border: `2px solid ${status === "done" ? "var(--success)" : status === "active" ? "var(--primary)" : "var(--border)"}`,
                  animation: status === "active" ? "pulse-glow 2s ease-in-out infinite" : "none",
                  transition: "all 0.3s",
                }}>
                  {status === "done"
                    ? <span style={{ color: "var(--success)", fontWeight: 700 }}>✓</span>
                    : status === "active"
                    ? <span style={{ animation: "blink 1.2s ease infinite" }}>{phase.icon}</span>
                    : <span style={{ opacity: 0.4 }}>{phase.icon}</span>}
                </div>
                <div>
                  <div style={{ fontWeight: 600, fontSize: "0.85rem", color: status === "done" ? "var(--success)" : status === "active" ? "var(--primary)" : "var(--text-dim)" }}>
                    {phase.label}
                  </div>
                  <div style={{ fontSize: "0.72rem", color: "var(--text-dim)", marginTop: 2 }}>{phase.desc}</div>
                </div>
              </div>
            </div>
            {i < PHASES.length - 1 && (
              <div style={{
                width: 24, height: 2, flexShrink: 0,
                background: getStatus(PHASES[i + 1].key) !== "pending" || status === "done" ? "var(--success)" : "var(--border)",
                transition: "background 0.4s", margin: "0 4px",
              }} />
            )}
          </div>
        );
      })}
    </div>
  );
}
