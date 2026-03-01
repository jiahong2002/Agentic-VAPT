const PHASES = [
  {
    key: "design",
    icon: "🏗",
    label: "Design",
    subtitle: "STRIDE Threat Modeling",
    desc: "Codex analyses your application architecture and generates a complete STRIDE threat model before a single line of code is written.",
    tools: ["STRIDE Analysis", "Attack Surface Mapping", "Risk Prioritisation"],
  },
  {
    key: "development",
    icon: "⌨",
    label: "Development",
    subtitle: "SAST Code Analysis",
    desc: "Paste your code and Codex performs static analysis to identify injection flaws, broken auth, hardcoded secrets, and more.",
    tools: ["Static Analysis", "CWE Mapping", "Fix Suggestions"],
  },
  {
    key: "deployment",
    icon: "🚀",
    label: "Deployment",
    subtitle: "DAST + Penetration Testing",
    desc: "Provide a URL and Codex orchestrates ZAP to run vulnerability assessment, then assigns one agent per finding for PT verification.",
    tools: ["OWASP ZAP", "Parallel PT Agents", "HTML Report"],
  },
];

export default function SDLCSelector({ onSelect }) {
  return (
    <div>
      <div className="hero-section">
        <div className="hero-title">Human-Governed AI Security</div>
        <div className="hero-sub">
          Select your SDLC phase — Codex agents handle the analysis, humans retain the final veto
        </div>
      </div>

      <div className="phase-select-grid">
        {PHASES.map((phase) => (
          <button key={phase.key} className="phase-select-card" onClick={() => onSelect(phase.key)}>
            <div className="phase-select-icon">{phase.icon}</div>
            <div className="phase-select-label">{phase.label}</div>
            <div className="phase-select-subtitle">{phase.subtitle}</div>
            <div className="phase-select-desc">{phase.desc}</div>
            <div className="phase-select-tools">
              {phase.tools.map((t) => (
                <span key={t} className="tool-chip">{t}</span>
              ))}
            </div>
            <div className="phase-select-cta">Start {phase.label} Scan →</div>
          </button>
        ))}
      </div>
    </div>
  );
}
