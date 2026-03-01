const PHASES = [
  { key: "va", label: "Vulnerability Assessment" },
  { key: "approval", label: "Human Approval" },
  { key: "pt", label: "Penetration Testing" },
  { key: "report", label: "Report" },
];

const STATE_TO_PHASE = {
  IDLE: -1,
  VA_RUNNING: 0,
  VA_COMPLETE: 0,
  AWAITING_PT_APPROVAL: 1,
  PT_RUNNING: 2,
  PT_COMPLETE: 2,
  REPORT_READY: 3,
  ERROR: -1,
};

export default function PhaseTracker({ state }) {
  const activeIdx = STATE_TO_PHASE[state] ?? -1;

  return (
    <div className="phase-tracker">
      {PHASES.map((phase, idx) => {
        const done = idx < activeIdx;
        const active = idx === activeIdx;
        return (
          <div key={phase.key} className={`phase-step ${done ? "done" : ""} ${active ? "active" : ""}`}>
            <div className="phase-dot">
              {done ? "✓" : idx + 1}
            </div>
            <div className="phase-label">{phase.label}</div>
            {idx < PHASES.length - 1 && <div className="phase-line" />}
          </div>
        );
      })}
    </div>
  );
}
