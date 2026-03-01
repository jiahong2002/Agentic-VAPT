import { useState } from "react";

/**
 * GreenlightPanel — formal human-in-the-loop approval gate.
 *
 * Props:
 *   phase         – "design" | "development" | "deployment"
 *   findings      – array of {id, name, severity, ...}  (threats / sast / va findings)
 *   initiatedBy   – name of the person who started the scan (for 4-eyes enforcement)
 *   onGreenlight  – fn({ approved_finding_ids, greenlighted_by, risk_acknowledgement })
 *   onSkip        – fn() — generate report without PT (deployment only)
 *   loading       – boolean
 */
export default function GreenlightPanel({ phase, findings, initiatedBy, onGreenlight, onSkip, loading }) {
  const [approver, setApprover] = useState("");
  const [selected, setSelected] = useState(() => new Set(findings.map(f => f.id)));
  const [ack, setAck] = useState(false);
  const [error, setError] = useState("");

  const toggle = (id) => {
    setSelected(prev => {
      const s = new Set(prev);
      s.has(id) ? s.delete(id) : s.add(id);
      return s;
    });
  };

  const selectAll = () => setSelected(new Set(findings.map(f => f.id)));
  const clearAll = () => setSelected(new Set());

  const handleSubmit = () => {
    setError("");
    if (!approver.trim()) { setError("Please enter your name as the approver."); return; }
    if (approver.trim().toLowerCase() === initiatedBy?.trim().toLowerCase()) {
      setError("4-eyes principle: you cannot approve your own scan. A different person must greenlight.");
      return;
    }
    if (!ack) { setError("You must acknowledge the risk before proceeding."); return; }
    if (selected.size === 0) { setError("Select at least one finding to include in the report."); return; }
    onGreenlight({
      approved_finding_ids: [...selected],
      greenlighted_by: approver.trim(),
      risk_acknowledgement: true,
    });
  };

  const sevClass = (s) => {
    if (!s) return "";
    const sl = (s.risk_level || s.severity || "").toLowerCase();
    return `sev-badge sev-${sl}`;
  };

  const sevLabel = (f) => f.risk_level || f.severity || "";

  return (
    <div>
      {/* Greenlight header */}
      <div className="card greenlight-header-card">
        <div style={{ display: "flex", alignItems: "center", gap: "0.75rem", marginBottom: "0.75rem" }}>
          <span style={{ fontSize: "1.5rem" }}>🟢</span>
          <div>
            <h2 className="card-title" style={{ marginBottom: 0 }}>Greenlight Approval</h2>
            <p style={{ color: "var(--muted)", fontSize: "0.85rem", marginTop: "0.2rem" }}>
              {phase === "deployment"
                ? "Review VA findings and greenlight for active penetration testing."
                : "Review findings and approve the signed security report."}
            </p>
          </div>
        </div>

        <div className="gl-4eyes-notice">
          <span>🔒</span>
          <span>
            <strong>4-Eyes Principle enforced.</strong>{" "}
            Scan initiated by <code>{initiatedBy || "unknown"}</code>. A <em>different</em> person
            must provide the Greenlight approval.
          </span>
        </div>
      </div>

      {/* Finding selection */}
      <div className="card">
        <div className="va-header">
          <h3 style={{ fontSize: "1rem", fontWeight: 700, color: "#f0f6ff" }}>
            Select Findings to Approve ({selected.size}/{findings.length})
          </h3>
          <div style={{ display: "flex", gap: "0.5rem" }}>
            <button className="btn btn-ghost btn-sm" onClick={selectAll}>All</button>
            <button className="btn btn-ghost btn-sm" onClick={clearAll}>None</button>
          </div>
        </div>

        {findings.map((f) => {
          const isSelected = selected.has(f.id);
          return (
            <div
              key={f.id}
              className={`finding-card${isSelected ? " selected" : ""}`}
              onClick={() => toggle(f.id)}
            >
              <div className="finding-row">
                <input
                  type="checkbox"
                  className="finding-checkbox"
                  checked={isSelected}
                  onChange={() => toggle(f.id)}
                  onClick={e => e.stopPropagation()}
                />
                <div className="finding-body">
                  <div className="finding-header-row">
                    <span className="finding-name">{f.name || f.threat}</span>
                    <span className={sevClass(f)}>{sevLabel(f)}</span>
                    {f.cwe && <span className="cwe-badge">{f.cwe}</span>}
                  </div>
                  {f.description && (
                    <p style={{ fontSize: "0.84rem", color: "var(--muted)", marginTop: "0.25rem" }}>
                      {f.description}
                    </p>
                  )}
                  {f.mitigation && (
                    <p style={{ fontSize: "0.84rem", color: "var(--muted)", marginTop: "0.25rem" }}>
                      Mitigation: {f.mitigation}
                    </p>
                  )}
                  {f.url && (
                    <div className="finding-url">{f.url}</div>
                  )}
                </div>
              </div>
            </div>
          );
        })}
      </div>

      {/* Approval form */}
      <div className="card">
        <h3 style={{ fontSize: "1rem", fontWeight: 700, color: "#f0f6ff", marginBottom: "1rem" }}>
          Formal Approval
        </h3>

        <div className="field-group" style={{ marginBottom: "1rem" }}>
          <label className="field-label">Approver Name <span style={{ color: "var(--critical)" }}>*</span></label>
          <input
            className="url-input"
            placeholder="Enter your full name (must differ from initiator)"
            value={approver}
            onChange={e => setApprover(e.target.value)}
            disabled={loading}
          />
        </div>

        <label className="gl-ack-row">
          <input
            type="checkbox"
            checked={ack}
            onChange={e => setAck(e.target.checked)}
            disabled={loading}
            style={{ width: 16, height: 16, flexShrink: 0, accentColor: "var(--accent)" }}
          />
          <span>
            {phase === "deployment"
              ? "I acknowledge that active penetration testing will be performed. I confirm written authorisation exists for the target system."
              : "I have individually reviewed each selected finding and authorise the generation of the signed security report."}
          </span>
        </label>

        {error && <div className="gl-error">{error}</div>}

        <div className="approval-actions" style={{ marginTop: "1.25rem" }}>
          {phase === "deployment" && onSkip && (
            <button className="btn btn-ghost" onClick={onSkip} disabled={loading}>
              Skip PT — VA Report Only
            </button>
          )}
          <button
            className="btn btn-primary"
            onClick={handleSubmit}
            disabled={loading || !approver.trim() || !ack || selected.size === 0}
          >
            {loading ? "Processing…" : "🟢 Greenlight →"}
          </button>
        </div>
      </div>
    </div>
  );
}
