import { useState, useEffect, useRef, useCallback } from "react";
import SDLCSelector from "./components/SDLCSelector";
import { DesignInput, ThreatModelViewer } from "./components/DesignPhase";
import { DevInput, SASTViewer } from "./components/DevPhase";
import URLInput from "./components/URLInput";
import GreenlightPanel from "./components/GreenlightPanel";
import AgentDashboard from "./components/AgentDashboard";
import PTResults from "./components/PTResults";
import PTEducation from "./components/PTEducation";
import ReportViewer from "./components/ReportViewer";
import AuditLog from "./components/AuditLog";
import LiveLog from "./components/LiveLog";
import {
  startDesignScan, startDevScan, startDeploymentScan,
  getStatus, getResults,
  greenlightScan, skipPT,
  getPTResults, getAgentStatuses, getAuditLog,
} from "./api";

const POLL_MS = 2500;

// Lightweight VA findings summary shown before the Greenlight panel (deployment phase)
function VAFindings({ findings, onProceed }) {
  const counts = { Critical: 0, High: 0, Medium: 0, Low: 0, Informational: 0 };
  findings.forEach(f => { counts[f.severity] = (counts[f.severity] || 0) + 1; });
  return (
    <div>
      <div className="card">
        <h2 className="card-title">Vulnerability Assessment Complete</h2>
        <p style={{ color: "var(--muted)", fontSize: "0.9rem", marginBottom: "1rem" }}>
          Codex analysed {findings.length} finding{findings.length !== 1 ? "s" : ""}. Review below, then proceed to Greenlight for formal approval.
        </p>
        <div className="stats-row">
          {Object.entries(counts).map(([sev, cnt]) =>
            cnt > 0 && <span key={sev} className={`stat-pill stat-${sev.toLowerCase()}`}>{cnt} {sev}</span>
          )}
        </div>
      </div>
      {findings.map(f => (
        <div key={f.id} className="card" style={{ marginBottom: "0.75rem" }}>
          <div className="finding-header-row">
            <span className="finding-name">{f.name}</span>
            <span className={`sev-badge sev-${f.severity.toLowerCase()}`}>{f.severity}</span>
            {f.cwe && <span className="cwe-badge">{f.cwe}</span>}
          </div>
          {f.url && <div className="finding-url">{f.url}</div>}
          <p style={{ fontSize: "0.85rem", color: "var(--muted)", marginTop: "0.35rem" }}>{f.ai_explanation}</p>
        </div>
      ))}
      <div className="approval-bar">
        <p style={{ fontSize: "0.88rem", color: "var(--muted)" }}>
          Review the findings above. Proceed to Greenlight to approve active penetration testing.
        </p>
        <div className="approval-actions">
          <button className="btn btn-primary" onClick={onProceed}>Proceed to Greenlight →</button>
        </div>
      </div>
    </div>
  );
}

// Map phase key to a readable label for the header badge
const PHASE_LABELS = { design: "Design", development: "Development", deployment: "Deployment" };

export default function App() {
  // ── SDLC phase selection ────────────────────────────────────────────────
  const [selectedPhase, setSelectedPhase] = useState(null);  // null → show selector

  // ── Session state ───────────────────────────────────────────────────────
  const [sessionId, setSessionId] = useState(null);
  const [sessionState, setSessionState] = useState("IDLE");
  const [sessionPhase, setSessionPhase] = useState(null);
  const [initiatedBy, setInitiatedBy] = useState("");

  // ── Results ─────────────────────────────────────────────────────────────
  const [threatModel, setThreatModel] = useState(null);
  const [sastFindings, setSastFindings] = useState([]);
  const [vaFindings, setVaFindings] = useState([]);
  const [ptResults, setPtResults] = useState([]);
  const [agents, setAgents] = useState([]);
  const [auditEntries, setAuditEntries] = useState([]);

  // ── UI state ─────────────────────────────────────────────────────────────
  const [loading, setLoading] = useState(false);
  const [glLoading, setGlLoading] = useState(false);
  const [statusMsg, setStatusMsg] = useState("");
  const [error, setError] = useState("");
  const [showGreenlight, setShowGreenlight] = useState(false);
  // Live progress
  const [progressLog, setProgressLog] = useState([]);
  const [spiderProgress, setSpiderProgress] = useState(0);
  const [scanProgress, setScanProgress] = useState(0);

  const pollRef = useRef(null);

  // ── Polling ──────────────────────────────────────────────────────────────
  const stopPolling = () => {
    if (pollRef.current) { clearInterval(pollRef.current); pollRef.current = null; }
  };

  const fetchAuditLog = useCallback(async (sid) => {
    try {
      const data = await getAuditLog(sid);
      setAuditEntries(data.audit_log ?? []);
    } catch (_) {}
  }, []);

  const poll = useCallback(async (sid) => {
    try {
      const status = await getStatus(sid);
      setSessionState(status.state);

      // Always update progress data
      if (status.progress_log) setProgressLog(status.progress_log);
      if (status.spider_progress != null) setSpiderProgress(status.spider_progress);
      if (status.scan_progress != null) setScanProgress(status.scan_progress);

      if (status.state === "RUNNING") {
        setStatusMsg("Codex agent is analysing…");
      } else if (status.state === "PT_RUNNING" || status.state === "GREENLIGHTED") {
        setStatusMsg("Parallel Codex agents verifying vulnerabilities…");
        try {
          const agentData = await getAgentStatuses(sid);
          setAgents(agentData.agents ?? []);
        } catch (_) {}
      } else if (status.state === "AWAITING_GREENLIGHT") {
        setStatusMsg("");
        stopPolling();
        // Load results so we can show them + Greenlight panel
        try {
          const res = await getResults(sid);
          setThreatModel(res.threat_model ?? null);
          setSastFindings(res.sast_findings ?? []);
          setVaFindings(res.va_findings ?? []);
        } catch (_) {}
        fetchAuditLog(sid);
      } else if (status.state === "REPORT_READY") {
        setStatusMsg("Report ready.");
        stopPolling();
        try {
          const ptData = await getPTResults(sid);
          setPtResults(ptData.results ?? []);
          const agentData = await getAgentStatuses(sid);
          setAgents(agentData.agents ?? []);
        } catch (_) {}
        fetchAuditLog(sid);
      } else if (status.state === "ERROR") {
        setError(status.error_message ?? "An error occurred.");
        stopPolling();
      }
    } catch {
      setError("Lost connection to backend. Is the server running?");
      stopPolling();
    }
  }, [fetchAuditLog]);

  const startPolling = useCallback((sid) => {
    stopPolling();
    poll(sid);
    pollRef.current = setInterval(() => poll(sid), POLL_MS);
  }, [poll]);

  useEffect(() => () => stopPolling(), []);

  // ── Start handlers per phase ──────────────────────────────────────────────
  const handleDesignStart = async (body) => {
    setLoading(true); setError(""); setStatusMsg("Generating STRIDE threat model…");
    setInitiatedBy(body.initiated_by);
    try {
      const data = await startDesignScan(body);
      setSessionId(data.session_id);
      setSessionPhase("design");
      setSessionState(data.state);
      startPolling(data.session_id);
    } catch (err) {
      setError(err.response?.data?.detail ?? "Failed to start design scan.");
    } finally { setLoading(false); }
  };

  const handleDevStart = async (body) => {
    setLoading(true); setError(""); setStatusMsg("Running SAST analysis…");
    setInitiatedBy(body.initiated_by);
    try {
      const data = await startDevScan(body);
      setSessionId(data.session_id);
      setSessionPhase("development");
      setSessionState(data.state);
      startPolling(data.session_id);
    } catch (err) {
      setError(err.response?.data?.detail ?? "Failed to start SAST scan.");
    } finally { setLoading(false); }
  };

  const handleDeployStart = async (url) => {
    setLoading(true); setError(""); setStatusMsg("Starting vulnerability assessment…");
    setInitiatedBy("Security Engineer");
    try {
      const data = await startDeploymentScan({ url, initiated_by: "Security Engineer" });
      setSessionId(data.session_id);
      setSessionPhase("deployment");
      setSessionState(data.state);
      startPolling(data.session_id);
    } catch (err) {
      setError(err.response?.data?.detail ?? "Failed to start deployment scan.");
    } finally { setLoading(false); }
  };

  // ── Greenlight ────────────────────────────────────────────────────────────
  const handleGreenlight = async (body) => {
    setGlLoading(true); setError("");
    try {
      await greenlightScan(sessionId, body);
      setShowGreenlight(false);
      setSessionState("GREENLIGHTED");
      setStatusMsg(sessionPhase === "deployment"
        ? "Spawning parallel Codex PT agents…"
        : "Generating signed report…");
      startPolling(sessionId);
    } catch (err) {
      setError(err.response?.data?.detail ?? "Greenlight failed.");
    } finally { setGlLoading(false); }
  };

  const handleSkipPT = async () => {
    setGlLoading(true); setError("");
    try {
      await skipPT(sessionId);
      setShowGreenlight(false);
      setSessionState("GREENLIGHTED");
      setStatusMsg("Generating VA-only report…");
      startPolling(sessionId);
    } catch (err) {
      setError(err.response?.data?.detail ?? "Failed to skip PT.");
    } finally { setGlLoading(false); }
  };

  // ── Derived state helpers ─────────────────────────────────────────────────
  const isRunning = sessionState === "RUNNING" || sessionState === "GREENLIGHTED" || sessionState === "PT_RUNNING";
  const awaitingGreenlight = sessionState === "AWAITING_GREENLIGHT";
  const reportReady = sessionState === "REPORT_READY";
  const showAgents = agents.length > 0;

  // Findings to pass to Greenlight panel (phase-specific)
  const greenlightFindings =
    sessionPhase === "design" ? (threatModel?.threats ?? []) :
    sessionPhase === "development" ? sastFindings :
    vaFindings;

  // ── Reset ─────────────────────────────────────────────────────────────────
  const reset = () => {
    stopPolling();
    setSelectedPhase(null); setSessionId(null); setSessionState("IDLE"); setSessionPhase(null);
    setInitiatedBy(""); setThreatModel(null); setSastFindings([]); setVaFindings([]);
    setPtResults([]); setAgents([]); setAuditEntries([]);
    setLoading(false); setGlLoading(false); setStatusMsg(""); setError(""); setShowGreenlight(false);
    setProgressLog([]); setSpiderProgress(0); setScanProgress(0);
  };

  // ── Render ─────────────────────────────────────────────────────────────────
  return (
    <div className="app">
      <header className="app-header">
        <div className="header-inner">
          <div className="logo" onClick={reset} style={{ cursor: "pointer" }} title="Back to home">
            <span className="logo-icon">🛡</span>
            <span className="logo-text">Agentic VAPT</span>
          </div>
          <div className="header-badges">
            <span className="header-badge">OpenAI Codex</span>
            <span className="header-badge">OWASP ZAP</span>
            {selectedPhase && (
              <span className="header-badge" style={{ color: "var(--accent2)", borderColor: "var(--accent)" }}>
                {PHASE_LABELS[selectedPhase]}
              </span>
            )}
            {sessionId && <span className="header-badge">#{sessionId.slice(0, 8)}</span>}
            {sessionId && (
              <button className="btn btn-ghost btn-sm" onClick={reset}>← New Scan</button>
            )}
          </div>
        </div>
      </header>

      <main className="main">
        {/* ── 0. Phase selector ─────────────────────────────────────────── */}
        {!selectedPhase && !sessionId && (
          <SDLCSelector onSelect={(phase) => { setSelectedPhase(phase); setError(""); }} />
        )}

        {/* ── Error banner ──────────────────────────────────────────────── */}
        {error && <div className="error-banner"><strong>Error:</strong> {error}</div>}

        {/* ── 1. Design Phase ───────────────────────────────────────────── */}
        {selectedPhase === "design" && !sessionId && (
          <DesignInput onStart={handleDesignStart} loading={loading} />
        )}
        {sessionPhase === "design" && isRunning && (
          <div className="card" style={{ marginBottom: "1rem" }}>
            <div style={{ display: "flex", alignItems: "center", gap: "0.875rem" }}>
              <div className="spinner" style={{ width: 32, height: 32, borderWidth: 2 }} />
              <p className="status-msg" style={{ margin: 0 }}>{statusMsg}</p>
            </div>
          </div>
        )}
        {sessionPhase === "design" && (isRunning || awaitingGreenlight) && (
          <LiveLog messages={progressLog} phase="design" />
        )}
        {sessionPhase === "design" && awaitingGreenlight && !showGreenlight && threatModel && (
          <ThreatModelViewer threatModel={threatModel} onProceed={() => setShowGreenlight(true)} />
        )}

        {/* ── 2. Development Phase ──────────────────────────────────────── */}
        {selectedPhase === "development" && !sessionId && (
          <DevInput onStart={handleDevStart} loading={loading} />
        )}
        {sessionPhase === "development" && isRunning && (
          <div className="card" style={{ marginBottom: "1rem" }}>
            <div style={{ display: "flex", alignItems: "center", gap: "0.875rem" }}>
              <div className="spinner" style={{ width: 32, height: 32, borderWidth: 2 }} />
              <p className="status-msg" style={{ margin: 0 }}>{statusMsg}</p>
            </div>
          </div>
        )}
        {sessionPhase === "development" && (isRunning || awaitingGreenlight) && (
          <LiveLog messages={progressLog} phase="development" />
        )}
        {sessionPhase === "development" && awaitingGreenlight && !showGreenlight && sastFindings.length > 0 && (
          <SASTViewer findings={sastFindings} onProceed={() => setShowGreenlight(true)} />
        )}

        {/* ── 3. Deployment Phase ───────────────────────────────────────── */}
        {selectedPhase === "deployment" && !sessionId && (
          <URLInput onStart={handleDeployStart} loading={loading} />
        )}
        {sessionPhase === "deployment" && isRunning && (
          <div className="card" style={{ marginBottom: "1rem" }}>
            <div style={{ display: "flex", alignItems: "center", gap: "0.875rem" }}>
              <div className="spinner" style={{ width: 32, height: 32, borderWidth: 2 }} />
              <p className="status-msg" style={{ margin: 0 }}>{statusMsg}</p>
            </div>
          </div>
        )}
        {sessionPhase === "deployment" && (isRunning || awaitingGreenlight) && (
          <LiveLog
            messages={progressLog}
            spiderProgress={spiderProgress}
            scanProgress={scanProgress}
            phase="deployment"
          />
        )}
        {sessionPhase === "deployment" && isRunning && showAgents && (
          <AgentDashboard agents={agents} state={sessionState} />
        )}
        {sessionPhase === "deployment" && awaitingGreenlight && !showGreenlight && vaFindings.length > 0 && (
          <VAFindings findings={vaFindings} onProceed={() => setShowGreenlight(true)} />
        )}

        {/* ── Greenlight Panel (all phases) ─────────────────────────────── */}
        {showGreenlight && awaitingGreenlight && (
          <GreenlightPanel
            phase={sessionPhase}
            findings={greenlightFindings}
            initiatedBy={initiatedBy}
            onGreenlight={handleGreenlight}
            onSkip={sessionPhase === "deployment" ? handleSkipPT : null}
            loading={glLoading}
          />
        )}

        {/* ── PT running spinner (deployment, after greenlight) ─────────── */}
        {sessionPhase === "deployment" && sessionState === "PT_RUNNING" && (
          <>
            <div className="card" style={{ marginBottom: "1rem" }}>
              <div style={{ display: "flex", alignItems: "center", gap: "0.875rem" }}>
                <div className="spinner" style={{ width: 32, height: 32, borderWidth: 2 }} />
                <p className="status-msg" style={{ margin: 0 }}>{statusMsg}</p>
              </div>
            </div>
            <LiveLog
              messages={progressLog}
              spiderProgress={spiderProgress}
              scanProgress={scanProgress}
              phase="deployment"
            />
          </>
        )}

        {/* ── PT Results ────────────────────────────────────────────────── */}
        {reportReady && ptResults.length > 0 && (
          <>
            {showAgents && <AgentDashboard agents={agents} state={sessionState} />}
            <PTResults ptResults={ptResults} vaFindings={vaFindings} />
          </>
        )}

        {/* ── Educational: How the Pentest Was Done ─────────────────────── */}
        {reportReady && ptResults.length > 0 && (
          <PTEducation ptResults={ptResults} vaFindings={vaFindings} />
        )}

        {/* ── Report Viewer ─────────────────────────────────────────────── */}
        {reportReady && <ReportViewer sessionId={sessionId} />}

        {/* ── Audit Log ─────────────────────────────────────────────────── */}
        {auditEntries.length > 0 && <AuditLog entries={auditEntries} />}
      </main>
    </div>
  );
}
