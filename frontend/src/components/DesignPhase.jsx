import { useState } from "react";

const STRIDE_COLORS = {
  "Spoofing": "stride-s",
  "Tampering": "stride-t",
  "Repudiation": "stride-r",
  "Information Disclosure": "stride-i",
  "Denial of Service": "stride-d",
  "Elevation of Privilege": "stride-e",
};

const STRIDE_ABBR = {
  "Spoofing": "S", "Tampering": "T", "Repudiation": "R",
  "Information Disclosure": "I", "Denial of Service": "D", "Elevation of Privilege": "E",
};

export function DesignInput({ onStart, loading }) {
  const [appName, setAppName] = useState("");
  const [description, setDescription] = useState("");
  const [initiator, setInitiator] = useState("");

  const handleSubmit = (e) => {
    e.preventDefault();
    if (!appName.trim() || !description.trim() || !initiator.trim()) return;
    onStart({ app_name: appName.trim(), app_description: description.trim(), initiated_by: initiator.trim() });
  };

  return (
    <div className="card">
      <h2 className="card-title">🏗 STRIDE Threat Modeling</h2>
      <p className="card-desc">
        Describe your application and Codex will generate a complete threat model across all
        six STRIDE categories before development begins.
      </p>
      <form onSubmit={handleSubmit} style={{ display: "flex", flexDirection: "column", gap: "0.875rem" }}>
        <div className="field-group">
          <label className="field-label">Application Name</label>
          <input className="url-input" placeholder="e.g. Customer Portal API"
            value={appName} onChange={e => setAppName(e.target.value)} disabled={loading} />
        </div>
        <div className="field-group">
          <label className="field-label">Application Description</label>
          <textarea className="url-input textarea" rows={5}
            placeholder="Describe the application: what it does, key components, data it handles, external integrations, user types..."
            value={description} onChange={e => setDescription(e.target.value)} disabled={loading} />
        </div>
        <div className="field-group">
          <label className="field-label">Your Name (Initiator)</label>
          <input className="url-input" placeholder="e.g. Alice Chen"
            value={initiator} onChange={e => setInitiator(e.target.value)} disabled={loading} />
        </div>
        <button type="submit" className="btn btn-primary"
          disabled={loading || !appName.trim() || !description.trim() || !initiator.trim()}>
          {loading ? "Generating threat model…" : "Generate STRIDE Threat Model →"}
        </button>
      </form>
    </div>
  );
}

export function ThreatModelViewer({ threatModel, onProceed }) {
  if (!threatModel) return null;

  const byCategory = threatModel.threats.reduce((acc, t) => {
    acc[t.category] = acc[t.category] || [];
    acc[t.category].push(t);
    return acc;
  }, {});

  const riskCounts = { Critical: 0, High: 0, Medium: 0, Low: 0 };
  threatModel.threats.forEach(t => { riskCounts[t.risk_level] = (riskCounts[t.risk_level] || 0) + 1; });

  return (
    <div>
      <div className="card">
        <h2 className="card-title">STRIDE Threat Model — {threatModel.app_name}</h2>
        <p style={{ color: "var(--muted)", fontSize: "0.9rem", marginBottom: "1rem" }}>
          {threatModel.summary}
        </p>
        <div className="stats-row">
          {Object.entries(riskCounts).map(([level, count]) => (
            count > 0 && <span key={level} className={`stat-pill stat-${level.toLowerCase()}`}>
              {count} {level}
            </span>
          ))}
        </div>
      </div>

      {Object.entries(byCategory).map(([cat, threats]) => (
        <div key={cat} className="card" style={{ marginBottom: "1rem" }}>
          <div className="stride-category-header">
            <span className={`stride-badge ${STRIDE_COLORS[cat] || ""}`}>
              {STRIDE_ABBR[cat] || "?"}
            </span>
            <h3 style={{ fontSize: "1rem", fontWeight: 700, color: "#f0f6ff" }}>{cat}</h3>
            <span style={{ color: "var(--muted)", fontSize: "0.82rem" }}>{threats.length} threat{threats.length !== 1 ? "s" : ""}</span>
          </div>
          {threats.map((threat) => (
            <div key={threat.id} className="threat-card">
              <div className="finding-header-row">
                <span className="finding-name">{threat.threat}</span>
                <span className={`sev-badge sev-${threat.risk_level.toLowerCase()}`}>{threat.risk_level}</span>
              </div>
              <div className="threat-row">
                <div className="threat-field">
                  <label>Attack Vector</label>
                  <p>{threat.attack_vector}</p>
                </div>
                <div className="threat-field">
                  <label>Impact</label>
                  <p>{threat.impact}</p>
                </div>
              </div>
              <div className="threat-field" style={{ marginTop: "0.5rem" }}>
                <label>Mitigation</label>
                <p style={{ color: "var(--confirmed)" }}>{threat.mitigation}</p>
              </div>
            </div>
          ))}
        </div>
      ))}

      {threatModel.top_risks.length > 0 && (
        <div className="card">
          <h3 style={{ fontSize: "1rem", fontWeight: 700, color: "#f0f6ff", marginBottom: "0.75rem" }}>
            Top Risks to Address
          </h3>
          <ul className="bullet-list">
            {threatModel.top_risks.map((r, i) => <li key={i}>{r}</li>)}
          </ul>
        </div>
      )}

      <div className="approval-bar">
        <p style={{ fontSize: "0.88rem", color: "var(--muted)" }}>
          Review the threat model above. Proceed to Greenlight to approve mitigations and generate the signed report.
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
