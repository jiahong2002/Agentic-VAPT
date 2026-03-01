import { useEffect, useRef } from "react";
import type { LogEntry } from "../hooks/useWebSocket";

interface Props {
  log: LogEntry[];
}

const TYPE_CONFIG: Record<string, { color: string; label: string; bg: string }> = {
  system:   { color: "#64748b", label: "SYS",      bg: "rgba(100,116,139,0.1)" },
  phase:    { color: "#3b82f6", label: "PHASE",    bg: "rgba(59,130,246,0.1)" },
  agent:    { color: "#a78bfa", label: "AGENT",    bg: "rgba(167,139,250,0.1)" },
  tool:     { color: "#34d399", label: "TOOL",     bg: "rgba(52,211,153,0.1)" },
  finding:  { color: "#f59e0b", label: "VULN",     bg: "rgba(245,158,11,0.1)" },
  approval: { color: "#f97316", label: "GATE",     bg: "rgba(249,115,22,0.1)" },
  error:    { color: "#f87171", label: "ERROR",    bg: "rgba(248,113,113,0.1)" },
};

const SEVERITY_COLORS: Record<string, string> = {
  critical: "#dc2626", high: "#ea580c", medium: "#d97706", low: "#65a30d",
  info: "#3b82f6", success: "#22c55e",
};

export function LiveFeed({ log }: Props) {
  const bottomRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [log]);

  return (
    <div style={{
      background: "var(--surface)",
      border: "1px solid var(--border)",
      borderRadius: 10,
      height: 320,
      overflowY: "auto",
      fontFamily: "var(--mono)",
      fontSize: "0.78rem",
      lineHeight: 1.8,
    }}>
      {/* Header bar */}
      <div style={{
        position: "sticky", top: 0,
        background: "var(--card)",
        borderBottom: "1px solid var(--border)",
        padding: "0.5rem 1rem",
        display: "flex", alignItems: "center", gap: 8,
        zIndex: 1,
      }}>
        <div style={{ display: "flex", gap: 5 }}>
          {["#ef4444", "#f59e0b", "#22c55e"].map((c) => (
            <div key={c} style={{ width: 10, height: 10, borderRadius: "50%", background: c }} />
          ))}
        </div>
        <span style={{ color: "var(--text-dim)", fontSize: "0.75rem", marginLeft: 4 }}>agent.log</span>
        <div style={{ marginLeft: "auto", display: "flex", alignItems: "center", gap: 5 }}>
          <div style={{ width: 6, height: 6, borderRadius: "50%", background: "#22c55e", animation: log.length > 0 ? "blink 1.5s ease infinite" : "none" }} />
          <span style={{ color: "var(--text-dim)", fontSize: "0.7rem" }}>{log.length} events</span>
        </div>
      </div>

      {/* Log entries */}
      <div style={{ padding: "0.5rem 0" }}>
        {log.length === 0 ? (
          <div style={{ color: "var(--text-dim)", textAlign: "center", padding: "4rem 1rem", fontSize: "0.85rem" }}>
            <div style={{ fontSize: "2rem", marginBottom: 8 }}>⏳</div>
            Waiting for scan to start...
          </div>
        ) : (
          log.map((entry, i) => {
            const cfg = TYPE_CONFIG[entry.type] ?? { color: "#94a3b8", label: "LOG", bg: "transparent" };
            const sevColor = entry.severity ? SEVERITY_COLORS[entry.severity] : null;
            return (
              <div key={i} style={{
                display: "flex", gap: 0, padding: "1px 0",
                animation: i === log.length - 1 ? "fade-in 0.2s ease" : "none",
                borderLeft: i === log.length - 1 ? `2px solid ${sevColor ?? cfg.color}` : "2px solid transparent",
                paddingLeft: 0,
              }}>
                <span style={{ color: "var(--text-dim)", minWidth: 68, paddingLeft: 10, fontSize: "0.72rem" }}>{entry.time}</span>
                <span style={{
                  color: sevColor ?? cfg.color,
                  background: sevColor ? `${sevColor}18` : cfg.bg,
                  padding: "0 6px",
                  minWidth: 56,
                  textAlign: "center",
                  borderRadius: 3,
                  fontSize: "0.68rem",
                  fontWeight: 700,
                  letterSpacing: "0.05em",
                  margin: "0 8px",
                  alignSelf: "flex-start",
                  marginTop: 2,
                }}>
                  {cfg.label}
                </span>
                <span style={{ color: sevColor ? "#f1f5f9" : "#cbd5e1", wordBreak: "break-all", paddingRight: 10, flex: 1 }}>
                  {entry.text}
                </span>
              </div>
            );
          })
        )}
        <div ref={bottomRef} />
      </div>
    </div>
  );
}
