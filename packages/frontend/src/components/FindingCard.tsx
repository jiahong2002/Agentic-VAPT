import { useState } from "react";
import type { Finding } from "../hooks/useWebSocket";

interface Props {
  finding: Finding;
  index: number;
}

const SEV: Record<string, { color: string; bg: string; border: string; dot: string }> = {
  critical: { color: "#fca5a5", bg: "rgba(220,38,38,0.08)", border: "rgba(220,38,38,0.3)", dot: "#dc2626" },
  high:     { color: "#fdba74", bg: "rgba(234,88,12,0.08)",  border: "rgba(234,88,12,0.3)",  dot: "#ea580c" },
  medium:   { color: "#fcd34d", bg: "rgba(217,119,6,0.08)",  border: "rgba(217,119,6,0.3)",  dot: "#d97706" },
  low:      { color: "#86efac", bg: "rgba(101,163,13,0.08)", border: "rgba(101,163,13,0.3)", dot: "#65a30d" },
};

const TYPE_ICONS: Record<string, string> = {
  sqli: "💉", xss: "📝", file_exposure: "📂", header: "🔓",
};

export function FindingCard({ finding, index }: Props) {
  const [expanded, setExpanded] = useState(false);
  const s = SEV[finding.severity] ?? SEV.low;
  const hasDetails = !!(finding.evidence_steps?.length || finding.payload || finding.reproduction || finding.evidence);

  return (
    <div style={{
      background: s.bg,
      border: `1px solid ${s.border}`,
      borderRadius: 10,
      marginBottom: "0.6rem",
      animation: `fade-in 0.3s ease ${index * 0.05}s both`,
      overflow: "hidden",
    }}>
      {/* Header row — always visible */}
      <div
        style={{
          padding: "0.85rem",
          cursor: hasDetails ? "pointer" : "default",
          display: "flex", alignItems: "flex-start", gap: 8,
        }}
        onClick={() => hasDetails && setExpanded((v) => !v)}
      >
        <span style={{ fontSize: "1rem", flexShrink: 0, marginTop: 1 }}>
          {TYPE_ICONS[finding.type] ?? "⚠️"}
        </span>
        <div style={{ flex: 1, minWidth: 0 }}>
          <div style={{ display: "flex", alignItems: "center", gap: 6, marginBottom: 4, flexWrap: "wrap" }}>
            <span style={{
              background: s.dot, color: "white",
              padding: "1px 7px", borderRadius: 4,
              fontSize: "0.65rem", fontWeight: 800, letterSpacing: "0.06em",
            }}>
              {finding.severity.toUpperCase()}
            </span>
            <span style={{ fontWeight: 600, fontSize: "0.82rem", color: "var(--text-primary)", wordBreak: "break-word", flex: 1 }}>
              {finding.title}
            </span>
            {hasDetails && (
              <span style={{ color: "var(--text-dim)", fontSize: "0.7rem", flexShrink: 0 }}>
                {expanded ? "▲" : "▼"}
              </span>
            )}
          </div>
          <div style={{
            fontFamily: "var(--mono)", fontSize: "0.72rem",
            color: "var(--text-dim)", wordBreak: "break-all",
            background: "rgba(0,0,0,0.2)", padding: "2px 6px", borderRadius: 4,
          }}>
            {finding.endpoint}
          </div>
        </div>
      </div>

      {/* Expandable evidence section */}
      {expanded && hasDetails && (
        <div style={{
          borderTop: `1px solid ${s.border}`,
          padding: "0.85rem",
          animation: "fade-in 0.15s ease",
        }}>

          {/* Step-by-step evidence */}
          {finding.evidence_steps && finding.evidence_steps.length > 0 && (
            <div style={{ marginBottom: finding.payload ? "0.85rem" : 0 }}>
              <div style={{
                fontSize: "0.65rem", fontWeight: 700, textTransform: "uppercase",
                letterSpacing: "0.08em", color: "var(--text-dim)", marginBottom: "0.5rem",
              }}>
                How To Reproduce (Step-by-step)
              </div>
              <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
                {finding.evidence_steps.map((step, i) => (
                  <div key={i} style={{ display: "flex", gap: 8, alignItems: "flex-start" }}>
                    <div style={{
                      flexShrink: 0,
                      width: 20, height: 20,
                      borderRadius: "50%",
                      background: s.dot,
                      color: "white",
                      fontSize: "0.6rem", fontWeight: 800,
                      display: "flex", alignItems: "center", justifyContent: "center",
                    }}>
                      {i + 1}
                    </div>
                    <span style={{
                      fontSize: "0.75rem", color: "#cbd5e1",
                      lineHeight: 1.5, paddingTop: 2,
                    }}>
                      {/* Strip the "Step N:" prefix if the AI included it */}
                      {step.replace(/^step\s*\d+:\s*/i, "")}
                    </span>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Payload */}
          {finding.payload && (
            <div style={{ marginBottom: finding.reproduction || finding.evidence ? "0.85rem" : 0 }}>
              <div style={{
                fontSize: "0.65rem", fontWeight: 700, textTransform: "uppercase",
                letterSpacing: "0.08em", color: "var(--text-dim)", marginBottom: "0.4rem",
              }}>
                Payload
              </div>
              <div style={{
                fontFamily: "var(--mono)", fontSize: "0.72rem",
                background: "rgba(0,0,0,0.3)", color: s.color,
                padding: "0.4rem 0.6rem", borderRadius: 5,
                wordBreak: "break-all", lineHeight: 1.5,
                border: `1px solid ${s.border}`,
              }}>
                {finding.payload}
              </div>
            </div>
          )}

          {/* Reproduction command */}
          {finding.reproduction && (
            <div style={{ marginBottom: finding.evidence ? "0.85rem" : 0 }}>
              <div style={{
                fontSize: "0.65rem", fontWeight: 700, textTransform: "uppercase",
                letterSpacing: "0.08em", color: "var(--text-dim)", marginBottom: "0.4rem",
              }}>
                Reproduction
              </div>
              <div style={{
                fontFamily: "var(--mono)", fontSize: "0.72rem",
                background: "rgba(0,0,0,0.3)", color: "#e2e8f0",
                padding: "0.4rem 0.6rem", borderRadius: 5,
                wordBreak: "break-all", lineHeight: 1.5,
                border: `1px solid ${s.border}`,
              }}>
                {finding.reproduction}
              </div>
            </div>
          )}

          {/* Fallback plain evidence if no steps */}
          {!finding.evidence_steps?.length && finding.evidence && (
            <div>
              <div style={{
                fontSize: "0.65rem", fontWeight: 700, textTransform: "uppercase",
                letterSpacing: "0.08em", color: "var(--text-dim)", marginBottom: "0.4rem",
              }}>
                Evidence
              </div>
              <div style={{
                fontSize: "0.75rem", color: "#cbd5e1", lineHeight: 1.5,
              }}>
                {finding.evidence}
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
