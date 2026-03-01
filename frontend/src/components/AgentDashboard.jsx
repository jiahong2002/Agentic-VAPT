const SEV_COLORS = {
  Critical: "sev-critical", High: "sev-high",
  Medium: "sev-medium", Low: "sev-low", Informational: "sev-info",
};

const VERDICT_LABELS = {
  confirmed: "Confirmed",
  false_positive: "False Positive",
  inconclusive: "Inconclusive",
};

function AgentCard({ agent }) {
  const isRunning = agent.status === "running";
  const isDone = agent.status === "complete";

  let cardClass = "agent-card";
  if (isRunning) cardClass += " running";
  else if (isDone && agent.verdict) cardClass += ` complete-${agent.verdict}`;
  else if (agent.status === "error") cardClass += " error";

  return (
    <div className={cardClass}>
      <div className="agent-card-header">
        <span className="agent-id">Agent #{agent.agent_id}</span>
        <span className={`sev-badge ${SEV_COLORS[agent.severity] ?? "sev-info"}`}>
          {agent.severity}
        </span>
      </div>
      <div className="agent-finding-name">{agent.finding_name}</div>

      <div className="agent-status-row">
        <span className={`agent-status-dot dot-${agent.status}`} />
        <span className="agent-log">{agent.log ?? agent.status}</span>
      </div>

      {isDone && agent.verdict && (
        <span className={`verdict-badge verdict-${agent.verdict}`}>
          {VERDICT_LABELS[agent.verdict] ?? agent.verdict}
        </span>
      )}

      {isRunning && (
        <div className="agent-progress-bar">
          <div className="agent-progress-fill" style={{ width: "60%" }} />
        </div>
      )}
    </div>
  );
}

export default function AgentDashboard({ agents, state }) {
  if (!agents || agents.length === 0) return null;

  const running = agents.filter((a) => a.status === "running").length;
  const done = agents.filter((a) => a.status === "complete").length;
  const total = agents.length;

  return (
    <div style={{ marginBottom: "1.5rem" }}>
      <div className="agent-dashboard-header">
        <h2>
          Codex Agents — {done}/{total} complete
          {running > 0 && <span style={{ color: "var(--accent2)", marginLeft: "0.5rem", fontSize: "0.85rem" }}>
            ({running} running in parallel)
          </span>}
        </h2>
        <p>One dedicated Codex agent has been assigned to each vulnerability to verify it independently.</p>
      </div>
      <div className="agent-grid">
        {agents.map((agent) => (
          <AgentCard key={agent.agent_id} agent={agent} />
        ))}
      </div>
    </div>
  );
}
