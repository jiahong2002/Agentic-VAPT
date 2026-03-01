const EVENT_ICONS = {
  scan_started: "▶",
  threat_model_complete: "🏗",
  sast_complete: "⌨",
  va_complete: "🔍",
  finding_reviewed: "👁",
  greenlight_approved: "🟢",
  pt_started: "🚀",
  pt_skipped: "⏭",
  report_ready: "📄",
  error: "✗",
};

const EVENT_COLORS = {
  scan_started: "var(--accent)",
  threat_model_complete: "var(--accent2)",
  sast_complete: "var(--accent2)",
  va_complete: "var(--accent2)",
  finding_reviewed: "var(--muted)",
  greenlight_approved: "var(--confirmed)",
  pt_started: "var(--high)",
  pt_skipped: "var(--muted)",
  report_ready: "var(--confirmed)",
  error: "var(--critical)",
};

function formatTime(ts) {
  if (!ts) return "";
  try {
    return new Date(ts).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" });
  } catch {
    return ts;
  }
}

function formatEvent(event) {
  return event.replace(/_/g, " ").replace(/\b\w/g, c => c.toUpperCase());
}

export default function AuditLog({ entries }) {
  if (!entries || entries.length === 0) return null;

  return (
    <div className="card">
      <h3 style={{ fontSize: "1rem", fontWeight: 700, color: "#f0f6ff", marginBottom: "1.25rem" }}>
        Audit Trail
      </h3>
      <div className="audit-timeline">
        {entries.map((entry, i) => {
          const icon = EVENT_ICONS[entry.event] || "•";
          const color = EVENT_COLORS[entry.event] || "var(--muted)";
          const isLast = i === entries.length - 1;

          return (
            <div key={i} className="audit-item">
              <div className="audit-stem">
                <div className="audit-dot" style={{ background: color, borderColor: color }}>
                  <span className="audit-icon">{icon}</span>
                </div>
                {!isLast && <div className="audit-line" />}
              </div>
              <div className="audit-body">
                <div className="audit-header">
                  <span className="audit-event" style={{ color }}>
                    {formatEvent(entry.event)}
                  </span>
                  <span className="audit-time">{formatTime(entry.timestamp)}</span>
                </div>
                <div className="audit-actor">
                  <span className="audit-actor-label">Actor:</span>{" "}
                  <span style={{ color: entry.actor === "system" ? "var(--muted)" : "var(--text)" }}>
                    {entry.actor}
                  </span>
                </div>
                <div className="audit-detail">{entry.detail}</div>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}
