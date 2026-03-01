import { useState } from "react";

/**
 * PTEducation — "How the pentest was done" educational section.
 *
 * Props:
 *   ptResults   – list of PTResult objects (with attack_walkthrough)
 *   vaFindings  – list of VulnFinding objects (for name/severity lookup)
 */
export default function PTEducation({ ptResults, vaFindings }) {
  const [openId, setOpenId] = useState(null);

  // Only show confirmed findings that have a walkthrough
  const educational = ptResults.filter(
    (r) => r.status === "confirmed" && r.attack_walkthrough
  );

  if (educational.length === 0) return null;

  // Build a lookup for finding metadata
  const findingMap = {};
  vaFindings.forEach((f) => { findingMap[f.id] = f; });

  return (
    <div className="card">
      <div className="edu-header">
        <span className="edu-icon">📚</span>
        <div>
          <h2 className="card-title" style={{ marginBottom: 0 }}>
            How the Pentest Found These Vulnerabilities
          </h2>
          <p style={{ color: "var(--muted)", fontSize: "0.88rem", marginTop: "0.25rem" }}>
            Step-by-step breakdowns of the attack techniques used to confirm each vulnerability.
            Learning these helps you understand what to protect against.
          </p>
        </div>
      </div>

      <div style={{ display: "flex", flexDirection: "column", gap: "0.75rem", marginTop: "1.25rem" }}>
        {educational.map((result) => {
          const finding = findingMap[result.finding_id];
          const isOpen = openId === result.finding_id;
          const sev = (finding?.severity || "").toLowerCase();

          return (
            <div key={result.finding_id} className={`edu-card edu-card-${sev}`}>
              {/* Header — click to expand */}
              <button
                className="edu-card-toggle"
                onClick={() => setOpenId(isOpen ? null : result.finding_id)}
              >
                <div className="edu-card-title-row">
                  <span className="edu-vuln-icon">🔓</span>
                  <div className="edu-card-title-text">
                    <span className="edu-vuln-name">{finding?.name || "Vulnerability"}</span>
                    {finding && (
                      <span className={`sev-badge sev-${sev}`} style={{ marginLeft: "0.5rem" }}>
                        {finding.severity}
                      </span>
                    )}
                    {finding?.cwe && (
                      <span className="cwe-badge" style={{ marginLeft: "0.4rem" }}>{finding.cwe}</span>
                    )}
                  </div>
                </div>
                <span className="edu-chevron">{isOpen ? "▲" : "▼"}</span>
              </button>

              {/* Body — walkthrough content */}
              {isOpen && (
                <div className="edu-body">
                  {/* Quick context banner */}
                  {finding?.url && (
                    <div className="edu-target-url">
                      <span style={{ color: "var(--muted)" }}>Target:</span>{" "}
                      <code>{finding.url}</code>
                    </div>
                  )}

                  {/* The walkthrough steps */}
                  <div className="edu-walkthrough">
                    <WalkthroughRenderer text={result.attack_walkthrough} />
                  </div>

                  {/* Evidence */}
                  {result.evidence && (
                    <div className="edu-section">
                      <div className="edu-section-label">Evidence from Active Scan</div>
                      <pre className="edu-evidence-pre">{result.evidence}</pre>
                    </div>
                  )}

                  {/* Attack vector */}
                  {result.attack_vector && (
                    <div className="edu-section">
                      <div className="edu-section-label">Attack Vector Used</div>
                      <code className="edu-attack-vector">{result.attack_vector}</code>
                    </div>
                  )}

                  {/* Remediation */}
                  {finding?.solution && (
                    <div className="edu-section edu-remediation">
                      <div className="edu-section-label" style={{ color: "var(--confirmed)" }}>
                        🛡 How to Fix This
                      </div>
                      <p style={{ fontSize: "0.88rem", color: "var(--text)", marginTop: "0.35rem" }}>
                        {finding.solution}
                      </p>
                    </div>
                  )}
                </div>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
}


/**
 * Renders the attack walkthrough text, parsing numbered steps for nice formatting.
 * Handles both "1. Step text" and plain paragraph text.
 */
function WalkthroughRenderer({ text }) {
  if (!text) return null;

  // Split into lines and detect numbered steps
  const lines = text.split("\n").filter(Boolean);
  const rendered = [];
  let stepBuffer = null;

  lines.forEach((line, i) => {
    const stepMatch = line.match(/^(\d+)[.)]\s+(.+)/);
    if (stepMatch) {
      if (stepBuffer) rendered.push(stepBuffer);
      stepBuffer = { num: stepMatch[1], text: stepMatch[2] };
    } else if (stepBuffer) {
      // continuation of current step
      stepBuffer.text += " " + line.trim();
    } else {
      rendered.push({ type: "para", text: line });
    }
  });
  if (stepBuffer) rendered.push(stepBuffer);

  return (
    <div className="edu-steps">
      {rendered.map((item, i) => {
        if (item.type === "para") {
          return (
            <p key={i} className="edu-para">{item.text}</p>
          );
        }
        return (
          <div key={i} className="edu-step">
            <div className="edu-step-num">{item.num}</div>
            <div className="edu-step-text">{item.text}</div>
          </div>
        );
      })}
    </div>
  );
}
