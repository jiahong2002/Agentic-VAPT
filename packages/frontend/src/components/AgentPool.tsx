import type { AgentInfo } from "../hooks/useWebSocket";

interface Props {
  agents: AgentInfo[];
}

const TYPE_ICON: Record<string, string> = {
  sqli: "💉",
  xss: "📝",
  file_exposure: "📂",
  header: "🔓",
};

const STATUS_CONFIG: Record<
  AgentInfo["status"],
  { color: string; bg: string; border: string; label: string; dot?: string }
> = {
  spawned:  { color: "#94a3b8", bg: "rgba(148,163,184,0.06)", border: "rgba(148,163,184,0.15)", label: "SPAWNED" },
  running:  { color: "#3b82f6", bg: "rgba(59,130,246,0.08)",  border: "rgba(59,130,246,0.25)",  label: "RUNNING", dot: "#3b82f6" },
  done:     { color: "#22c55e", bg: "rgba(34,197,94,0.08)",   border: "rgba(34,197,94,0.25)",   label: "DONE" },
  skipped:  { color: "#64748b", bg: "rgba(100,116,139,0.06)", border: "rgba(100,116,139,0.15)", label: "SKIPPED" },
};

export function AgentPool({ agents }: Props) {
  if (agents.length === 0) return null;

  return (
    <div style={{
      background: "var(--card)",
      border: "1px solid var(--border)",
      borderRadius: 12,
      padding: "1.25rem",
      marginBottom: "1.25rem",
      animation: "fade-in 0.3s ease",
    }}>
      <div style={{
        fontSize: "0.72rem", fontWeight: 600, color: "var(--text-dim)",
        textTransform: "uppercase", letterSpacing: "0.08em",
        marginBottom: "1rem",
        display: "flex", alignItems: "center", gap: 8,
      }}>
        Agent Pool
        <span style={{
          background: "rgba(59,130,246,0.12)", color: "var(--primary)",
          borderRadius: 4, padding: "1px 7px", fontSize: "0.7rem", fontWeight: 700,
        }}>
          {agents.length} agent{agents.length !== 1 ? "s" : ""}
        </span>
        {agents.some((a) => a.status === "running") && (
          <div style={{ marginLeft: "auto", display: "flex", alignItems: "center", gap: 5 }}>
            <div style={{ width: 6, height: 6, borderRadius: "50%", background: "#3b82f6", animation: "blink 1.2s ease infinite" }} />
            <span style={{ fontSize: "0.7rem", color: "#3b82f6" }}>ACTIVE</span>
          </div>
        )}
      </div>

      <div style={{
        display: "grid",
        gridTemplateColumns: "repeat(auto-fill, minmax(220px, 1fr))",
        gap: "0.6rem",
      }}>
        {agents.map((agent) => {
          const cfg = STATUS_CONFIG[agent.status];
          return (
            <div
              key={agent.agentId}
              style={{
                background: cfg.bg,
                border: `1px solid ${cfg.border}`,
                borderRadius: 8,
                padding: "0.65rem 0.85rem",
                animation: "fade-in 0.25s ease",
              }}
            >
              {/* Agent ID + status row */}
              <div style={{ display: "flex", alignItems: "center", gap: 6, marginBottom: 6 }}>
                <span style={{
                  fontFamily: "var(--mono)", fontSize: "0.75rem",
                  fontWeight: 700, color: cfg.color,
                }}>
                  {agent.agentId}
                </span>
                <div style={{ marginLeft: "auto", display: "flex", alignItems: "center", gap: 4 }}>
                  {cfg.dot && (
                    <div style={{ width: 5, height: 5, borderRadius: "50%", background: cfg.dot, animation: "blink 1.2s ease infinite" }} />
                  )}
                  <span style={{
                    fontSize: "0.6rem", fontWeight: 700, letterSpacing: "0.06em",
                    color: cfg.color, textTransform: "uppercase",
                  }}>
                    {cfg.label}
                  </span>
                </div>
              </div>

              {/* Type + endpoint */}
              <div style={{ display: "flex", alignItems: "center", gap: 5, marginBottom: 4 }}>
                <span style={{ fontSize: "0.85rem" }}>
                  {TYPE_ICON[agent.candidateType] ?? "🔍"}
                </span>
                <span style={{
                  fontSize: "0.68rem", fontWeight: 700, textTransform: "uppercase",
                  color: "#94a3b8", letterSpacing: "0.05em",
                }}>
                  {agent.candidateType}
                </span>
              </div>
              <div style={{
                fontFamily: "var(--mono)", fontSize: "0.65rem",
                color: "var(--text-dim)", wordBreak: "break-all",
                lineHeight: 1.4,
              }}>
                {agent.endpoint.length > 48
                  ? "…" + agent.endpoint.slice(-45)
                  : agent.endpoint}
              </div>
              {agent.param && (
                <div style={{
                  marginTop: 4, fontFamily: "var(--mono)", fontSize: "0.62rem",
                  color: "#475569",
                }}>
                  param: {agent.param}
                </div>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
}
