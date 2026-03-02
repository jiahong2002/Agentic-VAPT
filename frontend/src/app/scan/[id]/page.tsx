'use client';

import { useEffect, useState, useRef } from 'react';
import { useParams, useRouter } from 'next/navigation';
import Link from 'next/link';
import styles from './scan.module.css';
import { apiFetch, API_BASE, getToken } from '../../../lib/auth';

type Phase = 'CRAWLING' | 'SCANNING' | 'SAST_CLONING' | 'SAST_ANALYZING' | 'AWAITING_APPROVAL' | 'EXPLOITING' | 'DONE' | 'ERROR';
type Severity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';
type AgentStatus = 'PENDING' | 'RUNNING' | 'CONFIRMED' | 'UNCONFIRMED' | 'ERROR';

interface Hypothesis {
  id: string;
  title: string;
  technique: string;
  severity: Severity;
  target_url: string;
  attack_surface: string;
}

interface AgentResult {
  hypothesis_id: string;
  title: string;
  status: AgentStatus;
  severity: Severity;
  technique: string;
  steps_count: number;
}

interface ScanSummary {
  urls_found?: number;
  forms_found?: number;
  tech_stack?: string[];
  header_issues?: number;
  discovered_urls?: string[];
  scanner_findings_count?: number;
}

interface SASTFinding {
  tool: string;
  rule_id: string;
  severity: Severity;
  file_path: string;
  line_number: number | null;
  message: string;
}

const PHASES: Phase[] = ['CRAWLING', 'SCANNING', 'AWAITING_APPROVAL', 'EXPLOITING', 'DONE'];
const PHASE_LABELS: Record<Phase, string> = {
  CRAWLING: 'Crawl',
  SCANNING: 'Recon',
  SAST_CLONING: 'SAST',
  SAST_ANALYZING: 'SAST',
  AWAITING_APPROVAL: 'Approve',
  EXPLOITING: 'Exploit',
  DONE: 'Report',
  ERROR: 'Error',
};

function severityClass(s: Severity) {
  return `badge badge-${s.toLowerCase()}`;
}

function agentStatusClass(s: AgentStatus) {
  return `badge badge-${s.toLowerCase()}`;
}

/** Extract the path + query portion from a URL for compact display in tabs. */
function urlPath(url: string): string {
  try {
    const u = new URL(url);
    const path = u.pathname;
    return path === '/' ? '/' : path.replace(/\/$/, '');
  } catch {
    return url;
  }
}

// ─── Exploit Progress Bar ─────────────────────────────────────────────────────
function ExploitProgress({ total, completed, startTime }: { total: number; completed: number; startTime?: number }) {
  const startRef = useRef<number>(startTime ?? Date.now());
  const [elapsed, setElapsed] = useState(() =>
    startTime ? Math.floor((Date.now() - startTime) / 1000) : 0
  );

  useEffect(() => {
    if (startTime) startRef.current = startTime;
  }, [startTime]);

  useEffect(() => {
    const id = setInterval(() => setElapsed(Math.floor((Date.now() - startRef.current) / 1000)), 1000);
    return () => clearInterval(id);
  }, []);

  const pct = total > 0 ? Math.round((completed / total) * 100) : 0;
  const remaining = total - completed;

  const fmt = (s: number) => {
    const m = Math.floor(s / 60);
    return m > 0 ? `${m}m ${s % 60}s` : `${s}s`;
  };

  return (
    <div className={styles.exploitProgress}>
      <div className={styles.exploitProgressHeader}>
        <span className={styles.exploitProgressLabel}>
          <span className={styles.pulse} />
          Testing in progress
        </span>
        <span className={styles.exploitProgressStats}>
          {completed} / {total} agents &nbsp;·&nbsp; {fmt(elapsed)} elapsed
        </span>
      </div>
      <div className={styles.exploitProgressTrack}>
        <div className={styles.exploitProgressFill} style={{ width: `${pct}%` }} />
      </div>
      <div className={styles.exploitProgressFooter}>
        <span>{pct}%</span>
        {remaining > 0 && <span>{remaining} agent{remaining !== 1 ? 's' : ''} still running</span>}
      </div>
    </div>
  );
}

// ─── Phase Timeline ───────────────────────────────────────────────────────────
function PhaseTimeline({ phase }: { phase: Phase }) {
  const current = PHASES.indexOf(phase);
  return (
    <div className={styles.timeline}>
      {PHASES.map((p, i) => {
        const done = i < current;
        const active = i === current;
        return (
          <div key={p} className={styles.timelineItem}>
            <div className={`${styles.timelineDot} ${done ? styles.done : active ? styles.active : styles.pending}`}>
              {done ? '✓' : i + 1}
            </div>
            <span className={`${styles.timelineLabel} ${active ? styles.activeLabel : ''}`}>
              {PHASE_LABELS[p]}
            </span>
            {i < PHASES.length - 1 && (
              <div className={`${styles.timelineLine} ${done ? styles.lineActive : ''}`} />
            )}
          </div>
        );
      })}
    </div>
  );
}

// ─── Approval Gate Modal ───────────────────────────────────────────────────────
function ApprovalGate({ scanId, hypotheses, onApproved, onCancel }: {
  scanId: string;
  hypotheses: Hypothesis[];
  onApproved: () => void;
  onCancel: () => void;
}) {
  const [checked, setChecked] = useState(false);
  const [loading, setLoading] = useState(false);

  const approve = async () => {
    setLoading(true);
    await apiFetch(`/api/scan/${scanId}/approve`, { method: 'POST' });
    onApproved();
  };

  const cancel = async () => {
    await apiFetch(`/api/scan/${scanId}/cancel`, { method: 'POST' });
    onCancel();
  };

  return (
    <div className={styles.modalBackdrop}>
      <div className={styles.modal}>
        <div className={styles.modalIcon}>⚠</div>
        <h2 className={styles.modalTitle}>Authorization Required</h2>
        <p className={styles.modalDesc}>
          The Recon Agent has assigned <strong>{hypotheses.length}</strong> vulnerability investigations.
          Each agent will form its own hypothesis, test it, and revise until all attack surfaces are covered.
        </p>

        <div className={styles.hypothesisList}>
          {hypotheses.slice(0, 8).map(h => (
            <div key={h.id} className={styles.hypothesisChip}>
              <span className={severityClass(h.severity)}>{h.severity}</span>
              <span className={styles.hypothesisTitle}>{h.title}</span>
            </div>
          ))}
          {hypotheses.length > 8 && (
            <div className={styles.moreChip}>+{hypotheses.length - 8} more</div>
          )}
        </div>

        <label className={styles.modalCheckLabel}>
          <input
            type="checkbox"
            id="approve-confirm"
            checked={checked}
            onChange={e => setChecked(e.target.checked)}
          />
          I confirm I am authorized to run these exploit agents against the target.
        </label>

        <div className={styles.modalActions}>
          <button className={styles.cancelBtn} onClick={cancel}>Cancel Scan</button>
          <button
            id="authorize-agents-btn"
            className={styles.approveBtn}
            disabled={!checked || loading}
            onClick={approve}
          >
            {loading ? <span className={styles.loadingDot} /> : null}
            Authorize Agents →
          </button>
        </div>
      </div>
    </div>
  );
}

// ─── Agent Card ───────────────────────────────────────────────────────────────
function AgentCard({ hypothesis, result }: { hypothesis: Hypothesis; result?: AgentResult }) {
  const status: AgentStatus = result?.status ?? 'PENDING';
  const severity = result?.severity ?? hypothesis.severity;
  return (
    <div className={`${styles.agentCard} ${styles[`agent${status}`]}`}>
      <div className={styles.agentHeader}>
        <span className={`${styles.agentStatus} ${agentStatusClass(status)}`}>{status}</span>
        <span className={severityClass(severity)}>{severity}</span>
      </div>
      <div className={styles.agentTitle}>{hypothesis.title}</div>
      <div className={styles.agentTech}>{result?.technique ?? hypothesis.technique}</div>
      {hypothesis.attack_surface && (
        <div className={styles.agentSurface}>{hypothesis.attack_surface}</div>
      )}
      {result && result.status === 'CONFIRMED' && (
        <div className={styles.agentSteps}>
          {result.steps_count} exploit steps documented
        </div>
      )}
      {status === 'RUNNING' && (
        <div className={styles.agentProgress}>
          <div className={styles.agentProgressBar} />
        </div>
      )}
    </div>
  );
}

// ─── URL Tab Bar ──────────────────────────────────────────────────────────────
function UrlTabBar({ hypotheses, selected, onSelect }: {
  hypotheses: Hypothesis[];
  selected: string | null;
  onSelect: (url: string | null) => void;
}) {
  // Unique URLs that have at least one hypothesis, preserving order of first appearance
  const seen = new Set<string>();
  const urls: string[] = [];
  for (const h of hypotheses) {
    if (h.target_url && !seen.has(h.target_url)) {
      seen.add(h.target_url);
      urls.push(h.target_url);
    }
  }

  if (urls.length === 0) return null;

  const countForUrl = (url: string | null) =>
    url === null
      ? hypotheses.length
      : hypotheses.filter(h => h.target_url === url).length;

  return (
    <div className={styles.urlTabBar}>
      <button
        className={`${styles.urlTab} ${selected === null ? styles.urlTabActive : ''}`}
        onClick={() => onSelect(null)}
      >
        All <span className={styles.urlTabCount}>{countForUrl(null)}</span>
      </button>
      {urls.map(url => (
        <button
          key={url}
          className={`${styles.urlTab} ${selected === url ? styles.urlTabActive : ''}`}
          onClick={() => onSelect(url)}
          title={url}
        >
          {urlPath(url)} <span className={styles.urlTabCount}>{countForUrl(url)}</span>
        </button>
      ))}
    </div>
  );
}

// ─── Main Scan Dashboard ──────────────────────────────────────────────────────
export default function ScanPage() {
  const { id: scanId } = useParams<{ id: string }>();
  const router = useRouter();

  const [phase, setPhase] = useState<Phase>('CRAWLING');
  const [message, setMessage] = useState('Initialising scan...');
  const [surface, setSurface] = useState<ScanSummary>({});
  const [hypotheses, setHypotheses] = useState<Hypothesis[]>([]);
  const [results, setResults] = useState<Map<string, AgentResult>>(new Map());
  const [showApproval, setShowApproval] = useState(false);
  const [approved, setApproved] = useState(false);
  const [cancelled, setCancelled] = useState(false);
  const [done, setDone] = useState(false);
  const [doneStats, setDoneStats] = useState({ total: 0, confirmed: 0 });
  const [logs, setLogs] = useState<string[]>([]);
  const [selectedUrl, setSelectedUrl] = useState<string | null>(null);
  const [stateLoaded, setStateLoaded] = useState(false);
  const [scanActive, setScanActive] = useState(true);
  const [exploitStartTime, setExploitStartTime] = useState<number | undefined>(undefined);
  const [sastFindings, setSastFindings] = useState<SASTFinding[]>([]);
  const logsRef = useRef<HTMLDivElement>(null);

  const addLog = (msg: string) => setLogs(prev => [...prev.slice(-50), msg]);

  // ── Step 1: Fetch snapshot to rehydrate on reconnect ─────────────────────
  useEffect(() => {
    if (!scanId) return;
    apiFetch(`/api/scan/${scanId}/state`)
      .then(res => res.ok ? res.json() : null)
      .then(data => {
        if (!data) return;
        const status = data.status as Phase;
        setPhase(status);

        // Restore a sensible status message
        const phaseMessages: Partial<Record<Phase, string>> = {
          CRAWLING: 'Crawling target...',
          SCANNING: 'Running recon agent...',
          AWAITING_APPROVAL: 'Awaiting exploit authorization...',
          EXPLOITING: 'Running exploit agents...',
          DONE: 'Scan complete.',
          ERROR: 'Scan ended with an error.',
        };
        setMessage(phaseMessages[status] ?? status);

        if (data.surface) setSurface(data.surface);
        if (data.hypotheses?.length) setHypotheses(data.hypotheses);
        if (data.agent_results?.length) {
          const map = new Map<string, AgentResult>();
          for (const r of data.agent_results) map.set(r.hypothesis_id, r);
          setResults(map);
        }
        if (data.done_stats) {
          setDone(true);
          setDoneStats(data.done_stats);
        }
        if (status === 'AWAITING_APPROVAL' && data.hypotheses?.length) {
          setShowApproval(true);
        }

        // Populate log from snapshot so it isn't blank on reconnect
        const syntheticLogs: string[] = [];
        if (data.surface) {
          syntheticLogs.push(
            `[Crawl] ${data.surface.urls_found} URLs, ${data.surface.forms_found} forms` +
            (data.surface.tech_stack?.length ? `, stack: ${data.surface.tech_stack.join(', ')}` : '')
          );
          if ((data.surface.header_issues ?? 0) > 0)
            syntheticLogs.push(`[Scan] ${data.surface.header_issues} security header issues detected`);
        }
        if (data.hypotheses?.length)
          syntheticLogs.push(`[Recon] ${data.hypotheses.length} vulnerability investigations assigned`);
        for (const r of (data.agent_results ?? []))
          syntheticLogs.push(`[Agent] ${r.title} → ${r.status} (${r.severity})`);
        if (syntheticLogs.length) setLogs(syntheticLogs);

        // Restore exploit elapsed timer from sessionStorage
        const stored = sessionStorage.getItem(`exploit_start_${scanId}`);
        if (stored) setExploitStartTime(parseInt(stored));

        const active = !['DONE', 'ERROR'].includes(status);
        setScanActive(active);
      })
      .catch(() => {})
      .finally(() => setStateLoaded(true));
  }, [scanId]);

  // ── Step 2: Connect to SSE only for still-running scans ───────────────────
  useEffect(() => {
    if (!scanId || !stateLoaded || !scanActive) return;
    const es = new EventSource(`${API_BASE}/api/scan/${scanId}/events?token=${encodeURIComponent(getToken() ?? '')}`);

    es.addEventListener('phase', e => {
      const d = JSON.parse(e.data);
      setPhase(d.phase as Phase);
      setMessage(d.message);
      addLog(`[Phase] ${d.message}`);
      if (d.phase === 'AWAITING_APPROVAL') setShowApproval(true);
      if (d.phase === 'EXPLOITING') {
        const key = `exploit_start_${scanId}`;
        if (!sessionStorage.getItem(key)) {
          const now = Date.now();
          sessionStorage.setItem(key, String(now));
          setExploitStartTime(now);
        }
      }
    });

    es.addEventListener('surface', e => {
      const d = JSON.parse(e.data);
      setSurface(d);
      addLog(`[Crawl] ${d.urls_found} URLs, ${d.forms_found} forms, stack: ${d.tech_stack?.join(', ') || 'unknown'}`);
    });

    es.addEventListener('hypotheses', e => {
      const d = JSON.parse(e.data);
      setHypotheses(d.hypotheses || []);
      addLog(`[Recon] ${d.count} vulnerability investigations assigned`);
    });

    es.addEventListener('sast_findings', e => {
      const d = JSON.parse(e.data);
      setSastFindings(d.findings || []);
      addLog(`[SAST] ${d.count} static analysis findings`);
    });

    es.addEventListener('agent_result', e => {
      const d = JSON.parse(e.data) as AgentResult;
      setResults(prev => new Map(prev).set(d.hypothesis_id, d));
      addLog(`[Agent] ${d.title} → ${d.status} (${d.severity})`);
    });

    es.addEventListener('done', e => {
      const d = JSON.parse(e.data);
      setDone(true);
      setDoneStats(d);
      setPhase('DONE');
      setScanActive(false);
      addLog(`[Done] ${d.confirmed}/${d.total} vulnerabilities confirmed`);
    });

    es.addEventListener('error', e => {
      const d = JSON.parse((e as any).data || '{}');
      setPhase('ERROR');
      setMessage(d.message || 'Unknown error');
      addLog(`[Error] ${d.message}`);
      es.close();
    });

    es.onerror = () => { es.close(); };

    return () => es.close();
  }, [scanId, stateLoaded, scanActive]);

  useEffect(() => {
    if (logsRef.current) {
      logsRef.current.scrollTop = logsRef.current.scrollHeight;
    }
  }, [logs]);

  if (cancelled) {
    return (
      <div className={styles.centred}>
        <div className={styles.cancelMsg}>Scan cancelled.</div>
        <button className={styles.backBtn} onClick={() => router.push('/')}>← New Scan</button>
      </div>
    );
  }

  const confirmedCount = Array.from(results.values()).filter(r => r.status === 'CONFIRMED').length;
  const runningCount = hypotheses.length - results.size;

  // Filter hypotheses by selected sub-page tab
  const visibleHypotheses = selectedUrl === null
    ? hypotheses
    : hypotheses.filter(h => h.target_url === selectedUrl);

  return (
    <div className={styles.page}>
      {/* Header */}
      <header className={styles.header}>
        <Link href="/dashboard" className={styles.logoLink}>
          <span className={styles.logoIcon}>⌖</span>
          AgentVAPT
        </Link>
        {scanActive && (
          <div className={styles.runningBadge}>
            <span className={styles.runningDot} />
            Running in background
          </div>
        )}
        <div className={styles.scanId}>
          <span className={styles.scanIdLabel}>SCAN</span>
          <code className={styles.scanIdCode}>{scanId?.slice(0, 8)}</code>
        </div>
      </header>

      {/* Phase Timeline */}
      <div className={styles.timelineWrapper}>
        <PhaseTimeline phase={phase} />
      </div>

      {/* Status Banner */}
      <div className={styles.statusBanner}>
        {phase !== 'DONE' && phase !== 'ERROR' && <span className={styles.pulse} />}
        <span className={styles.statusMsg}>{message}</span>
      </div>

      <div className={styles.body}>
        {/* Left column */}
        <div className={styles.left}>
          {/* Surface Summary */}
          {(surface.urls_found !== undefined || surface.forms_found !== undefined) && (
            <div className={styles.surfaceCard}>
              <div className={styles.cardTitle}>Attack Surface</div>
              <div className={styles.surfaceGrid}>
                <div className={styles.surfaceStat}>
                  <span className={styles.surfaceNum}>{surface.urls_found ?? 0}</span>
                  <span className={styles.surfaceLabel}>URLs</span>
                </div>
                <div className={styles.surfaceStat}>
                  <span className={styles.surfaceNum}>{surface.forms_found ?? 0}</span>
                  <span className={styles.surfaceLabel}>Forms</span>
                </div>
                <div className={styles.surfaceStat}>
                  <span
                    className={styles.surfaceNum}
                    style={{ color: (surface.scanner_findings_count ?? 0) > 0 ? '#ff6d00' : undefined }}
                  >
                    {surface.scanner_findings_count ?? '—'}
                  </span>
                  <span className={styles.surfaceLabel}>Nuclei Hits</span>
                </div>
              </div>
              {(surface.header_issues ?? 0) > 0 && (
                <div className={styles.headerIssueNote}>
                  ⚠ {surface.header_issues} security header issue{surface.header_issues !== 1 ? 's' : ''} detected
                </div>
              )}
              {surface.tech_stack && surface.tech_stack.length > 0 && (
                <div className={styles.techStack}>
                  {surface.tech_stack.map(t => (
                    <span key={t} className={styles.techBadge}>{t}</span>
                  ))}
                </div>
              )}
            </div>
          )}

          {/* SAST Findings Summary */}
          {sastFindings.length > 0 && (
            <div className={styles.surfaceCard}>
              <div className={styles.cardTitle}>SAST Findings</div>
              <div className={styles.surfaceGrid}>
                {(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'] as const).map(sev => {
                  const count = sastFindings.filter(f => f.severity === sev).length;
                  const colors: Record<string, string> = {
                    CRITICAL: '#dc2626', HIGH: '#ea580c', MEDIUM: '#ca8a04', LOW: '#16a34a',
                  };
                  return count > 0 ? (
                    <div key={sev} className={styles.surfaceStat}>
                      <span className={styles.surfaceNum} style={{ color: colors[sev] }}>{count}</span>
                      <span className={styles.surfaceLabel}>{sev}</span>
                    </div>
                  ) : null;
                })}
              </div>
            </div>
          )}

          {/* Exploit Stats */}
          {hypotheses.length > 0 && (
            <div className={styles.surfaceCard}>
              <div className={styles.cardTitle}>Agent Progress</div>
              <div className={styles.surfaceGrid}>
                <div className={styles.surfaceStat}>
                  <span className={styles.surfaceNum} style={{ color: '#06b6d4' }}>{hypotheses.length}</span>
                  <span className={styles.surfaceLabel}>Agents</span>
                </div>
                <div className={styles.surfaceStat}>
                  <span className={styles.surfaceNum} style={{ color: '#22c55e' }}>{confirmedCount}</span>
                  <span className={styles.surfaceLabel}>Confirmed</span>
                </div>
                <div className={styles.surfaceStat}>
                  <span className={styles.surfaceNum} style={{ color: '#a78bfa' }}>{runningCount}</span>
                  <span className={styles.surfaceLabel}>Running</span>
                </div>
              </div>
            </div>
          )}

          {/* Terminal Log */}
          <div className={styles.logCard}>
            <div className={styles.cardTitle}>Live Log</div>
            <div className={styles.logBody} ref={logsRef}>
              {logs.map((l, i) => (
                <div key={i} className={styles.logLine}>
                  <span className={styles.logPrompt}>{'>'}</span> {l}
                </div>
              ))}
              {logs.length === 0 && <div className={styles.logPlaceholder}>Waiting for events...</div>}
            </div>
          </div>
        </div>

        {/* Right column — Agent Cards */}
        <div className={styles.right}>
          {done && (
            <div className={styles.doneCard}>
              <div className={styles.doneTitle}>✓ Scan Complete</div>
              <div className={styles.doneStats}>
                <span><strong>{doneStats.confirmed}</strong> confirmed</span>
                <span><strong>{doneStats.total - doneStats.confirmed}</strong> unconfirmed</span>
              </div>
              <button
                id="view-report-btn"
                className={styles.reportBtn}
                onClick={() => router.push(`/scan/${scanId}/report`)}
              >
                View Full Report →
              </button>
            </div>
          )}

          {hypotheses.length === 0 && !done && (
            <div className={styles.waitingAgents}>
              <div className={styles.waitingSpinner} />
              <span>Awaiting investigation assignments...</span>
            </div>
          )}

          {/* Exploit progress bar — visible during active testing */}
          {phase === 'EXPLOITING' && hypotheses.length > 0 && !done && (
            <ExploitProgress total={hypotheses.length} completed={results.size} startTime={exploitStartTime} />
          )}

          {/* URL Tab Bar — appears once hypotheses are available */}
          {hypotheses.length > 0 && (
            <UrlTabBar
              hypotheses={hypotheses}
              selected={selectedUrl}
              onSelect={setSelectedUrl}
            />
          )}

          <div className={styles.agentGrid}>
            {visibleHypotheses.map(h => (
              <AgentCard key={h.id} hypothesis={h} result={results.get(h.id)} />
            ))}
          </div>

          {visibleHypotheses.length === 0 && hypotheses.length > 0 && selectedUrl && (
            <div className={styles.noAgentsMsg}>
              No agents assigned to this page yet.
            </div>
          )}
        </div>
      </div>

      {/* Approval Gate */}
      {showApproval && !approved && (
        <ApprovalGate
          scanId={scanId!}
          hypotheses={hypotheses}
          onApproved={() => { setShowApproval(false); setApproved(true); }}
          onCancel={() => { setCancelled(true); }}
        />
      )}
    </div>
  );
}
