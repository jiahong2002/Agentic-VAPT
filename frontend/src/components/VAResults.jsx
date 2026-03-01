import { useState } from "react";

const SEV_ORDER = { Critical: 0, High: 1, Medium: 2, Low: 3, Informational: 4 };

const SEV_COLORS = {
  Critical: "sev-critical",
  High: "sev-high",
  Medium: "sev-medium",
  Low: "sev-low",
  Informational: "sev-info",
};

export default function VAResults({ findings, onApprove, onSkip }) {
  const [selected, setSelected] = useState(new Set());
  const [approving, setApproving] = useState(false);

  const sorted = [...findings].sort(
    (a, b) => (SEV_ORDER[a.severity] ?? 9) - (SEV_ORDER[b.severity] ?? 9)
  );

  const toggle = (id) => {
    setSelected((prev) => {
      const next = new Set(prev);
      next.has(id) ? next.delete(id) : next.add(id);
      return next;
    });
  };

  const selectAll = () => setSelected(new Set(findings.map((f) => f.id)));
  const clearAll = () => setSelected(new Set());

  const handleApprove = async () => {
    setApproving(true);
    await onApprove([...selected]);
  };

  return (
    <div>
      <div className="card">
        <h2 className="card-title">VA Findings — {findings.length} vulnerabilities detected</h2>
        <p className="card-desc">
          The Codex agent has analysed the passive scan results below.
          Select which vulnerabilities you want the agent to actively verify via
          Penetration Testing, then click <strong>Approve PT</strong>.
        </p>
        <div className="bulk-actions">
          <button className="btn btn-ghost btn-sm" onClick={selectAll}>Select all</button>
          <button className="btn btn-ghost btn-sm" onClick={clearAll}>Clear</button>
          <span className="selected-count">{selected.size} of {findings.length} selected</span>
        </div>
      </div>

      {sorted.map((f) => (
        <div
          key={f.id}
          className={`finding-card ${selected.has(f.id) ? "selected" : ""}`}
          onClick={() => toggle(f.id)}
        >
          <div className="finding-row">
            <input
              type="checkbox"
              className="finding-checkbox"
              checked={selected.has(f.id)}
              onChange={() => toggle(f.id)}
              onClick={(e) => e.stopPropagation()}
            />
            <div className="finding-body">
              <div className="finding-header-row">
                <span className="finding-name">{f.name}</span>
                <span className={`sev-badge ${SEV_COLORS[f.severity]}`}>{f.severity}</span>
              </div>
              <div className="finding-url">{f.url}</div>
              <div className="finding-meta">
                {f.cwe && <span>CWE: {f.cwe}</span>}
                {f.cvss && <span>CVSS: {f.cvss}</span>}
                {f.pt_category && <span>PT Category: {f.pt_category}</span>}
              </div>
              <div className="finding-explanation">
                <label>AI Explanation</label>
                <p>{f.ai_explanation}</p>
              </div>
              <details className="finding-details">
                <summary>Technical details</summary>
                <p>{f.description}</p>
                {f.solution && <p className="solution"><strong>Fix:</strong> {f.solution}</p>}
              </details>
            </div>
          </div>
        </div>
      ))}

      <div className="approval-bar">
        <div className="approval-risk-warn">
          <span className="warn-icon">⚠</span>
          <span>
            Active penetration testing sends intrusive payloads to the target.
            Ensure you have written authorisation before proceeding.
          </span>
        </div>
        <div className="approval-actions">
          <button className="btn btn-ghost" onClick={onSkip} disabled={approving}>
            Skip PT — VA report only
          </button>
          <button
            className="btn btn-danger"
            disabled={selected.size === 0 || approving}
            onClick={handleApprove}
          >
            {approving ? "Starting PT…" : `Approve PT (${selected.size} selected)`}
          </button>
        </div>
      </div>
    </div>
  );
}
