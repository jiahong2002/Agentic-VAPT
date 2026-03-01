import { useState } from "react";

const CWE_COLORS = {
  Critical: "sev-critical",
  High: "sev-high",
  Medium: "sev-medium",
  Low: "sev-low",
  Informational: "sev-info",
};

export function DevInput({ onStart, loading }) {
  const [code, setCode] = useState("");
  const [fileCtx, setFileCtx] = useState("");
  const [initiator, setInitiator] = useState("");

  const handleSubmit = (e) => {
    e.preventDefault();
    if (!code.trim() || !initiator.trim()) return;
    onStart({ code_snippet: code.trim(), file_context: fileCtx.trim(), initiated_by: initiator.trim() });
  };

  return (
    <div className="card">
      <h2 className="card-title">⌨ SAST Code Analysis</h2>
      <p className="card-desc">
        Paste your code below and Codex will perform static analysis to identify injection flaws,
        broken authentication, hardcoded secrets, insecure dependencies, and CWE-mapped vulnerabilities.
      </p>
      <form onSubmit={handleSubmit} style={{ display: "flex", flexDirection: "column", gap: "0.875rem" }}>
        <div className="field-group">
          <label className="field-label">Your Name (Initiator)</label>
          <input className="url-input" placeholder="e.g. Bob Smith"
            value={initiator} onChange={e => setInitiator(e.target.value)} disabled={loading} />
        </div>
        <div className="field-group">
          <label className="field-label">File Context <span style={{ color: "var(--muted)", fontWeight: 400 }}>(optional — e.g. auth/login.py)</span></label>
          <input className="url-input" placeholder="e.g. src/api/auth.py"
            value={fileCtx} onChange={e => setFileCtx(e.target.value)} disabled={loading} />
        </div>
        <div className="field-group">
          <label className="field-label">Code Snippet</label>
          <textarea className="url-input code-textarea" rows={16}
            placeholder={"// Paste your code here…\nfunction login(username, password) {\n  const query = `SELECT * FROM users WHERE username='${username}'`;\n  ..."}
            value={code} onChange={e => setCode(e.target.value)} disabled={loading}
            spellCheck={false} />
        </div>
        <button type="submit" className="btn btn-primary"
          disabled={loading || !code.trim() || !initiator.trim()}>
          {loading ? "Analysing code…" : "Run SAST Analysis →"}
        </button>
      </form>
    </div>
  );
}

function ConfidenceBar({ confidence }) {
  const pct = Math.round((confidence ?? 0.8) * 100);
  const color = pct >= 80 ? "var(--confirmed)" : pct >= 50 ? "var(--medium)" : "var(--critical)";
  return (
    <div className="confidence-wrap">
      <div className="confidence-bar">
        <div className="confidence-fill" style={{ width: `${pct}%`, background: color }} />
      </div>
      <span className="confidence-label" style={{ color }}>{pct}%</span>
    </div>
  );
}

export function SASTViewer({ findings, onProceed }) {
  if (!findings || findings.length === 0) return null;

  const counts = { Critical: 0, High: 0, Medium: 0, Low: 0, Informational: 0 };
  findings.forEach(f => { counts[f.severity] = (counts[f.severity] || 0) + 1; });

  return (
    <div>
      <div className="card">
        <h2 className="card-title">SAST Analysis Results</h2>
        <div className="stats-row" style={{ marginTop: "0.75rem" }}>
          {Object.entries(counts).map(([sev, cnt]) =>
            cnt > 0 && (
              <span key={sev} className={`stat-pill stat-${sev.toLowerCase()}`}>
                {cnt} {sev}
              </span>
            )
          )}
        </div>
      </div>

      {findings.map((f) => (
        <div key={f.id} className={`card sast-card sast-${f.severity.toLowerCase()}`}>
          <div className="finding-header-row" style={{ marginBottom: "0.6rem" }}>
            <span className="finding-name">{f.name}</span>
            <span className={`sev-badge ${CWE_COLORS[f.severity] || "sev-info"}`}>{f.severity}</span>
            {f.cwe && <span className="cwe-badge">{f.cwe}</span>}
          </div>

          {(f.file_path || f.line) && (
            <div className="sast-location">
              <span className="sast-file">{f.file_path || "unknown"}</span>
              {f.line && <span className="sast-line">:{f.line}</span>}
            </div>
          )}

          <div className="sast-desc">{f.description}</div>

          <div className="sast-section">
            <label>AI Explanation</label>
            <p>{f.ai_explanation}</p>
          </div>

          {f.fix && (
            <div className="sast-section">
              <label>Suggested Fix</label>
              <p style={{ color: "var(--confirmed)" }}>{f.fix}</p>
            </div>
          )}

          <div className="sast-footer">
            <span className="sast-confidence-label">Confidence</span>
            <ConfidenceBar confidence={f.confidence} />
          </div>
        </div>
      ))}

      <div className="approval-bar">
        <p style={{ fontSize: "0.88rem", color: "var(--muted)" }}>
          Review all SAST findings above. Proceed to Greenlight to approve findings for the signed report.
        </p>
        <div className="approval-actions">
          <button className="btn btn-primary" onClick={onProceed}>
            Proceed to Greenlight →
          </button>
        </div>
      </div>
    </div>
  );
}
