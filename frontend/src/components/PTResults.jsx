const STATUS_CONFIG = {
  confirmed: { label: "Confirmed", cls: "status-confirmed" },
  false_positive: { label: "False Positive", cls: "status-fp" },
  inconclusive: { label: "Inconclusive", cls: "status-inconclusive" },
};

export default function PTResults({ ptResults, vaFindings }) {
  const findingMap = Object.fromEntries(vaFindings.map((f) => [f.id, f]));
  const confirmed = ptResults.filter((r) => r.status === "confirmed");
  const falsePos = ptResults.filter((r) => r.status === "false_positive");
  const inconclusive = ptResults.filter((r) => r.status === "inconclusive");

  return (
    <div>
      <div className="card">
        <h2 className="card-title">PT Results — Verification Complete</h2>
        <div className="pt-summary-row">
          <div className="pt-stat confirmed">{confirmed.length} Confirmed</div>
          <div className="pt-stat fp">{falsePos.length} False Positive</div>
          <div className="pt-stat inconclusive">{inconclusive.length} Inconclusive</div>
        </div>
      </div>

      {ptResults.map((r) => {
        const finding = findingMap[r.finding_id];
        const cfg = STATUS_CONFIG[r.status] ?? { label: r.status, cls: "" };
        return (
          <div key={r.finding_id} className={`finding-card pt-card pt-${r.status}`}>
            <div className="finding-header-row">
              <span className="finding-name">{finding?.name ?? r.finding_id}</span>
              <span className={`pt-badge ${cfg.cls}`}>{cfg.label}</span>
            </div>
            {finding && <div className="finding-url">{finding.url}</div>}
            <div className="finding-explanation">
              <label>Codex Verdict</label>
              <p>{r.explanation}</p>
            </div>
            {r.evidence && (
              <details className="finding-details">
                <summary>Evidence</summary>
                <pre className="evidence-pre">{r.evidence}</pre>
              </details>
            )}
            {r.attack_vector && (
              <div className="finding-explanation">
                <label>Attack Vector</label>
                <code className="attack-vector">{r.attack_vector}</code>
              </div>
            )}
          </div>
        );
      })}
    </div>
  );
}
