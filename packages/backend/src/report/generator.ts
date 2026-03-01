export interface ReportData {
  summary: {
    scan_date: string;
    total_findings: number;
    critical: number;
    high: number;
    medium: number;
    low: number;
  };
  executive_summary: string;
  findings: Array<{
    id: string;
    type: string;
    title: string;
    severity: "critical" | "high" | "medium" | "low";
    endpoint: string;
    description: string;
    evidence: string | null;
    evidence_steps: string[] | null;
    payload: string | null;
    reproduction: string | null;
    remediation: string;
    references: string[];
  }>;
  recommendations: string[];
}

interface StoredFinding {
  id: string;
  type: string;
  endpoint: string;
  evidence: string | null;
  evidence_steps: string[] | null;
  payload: string | null;
  reproduction: string | null;
}

interface NormalizedFinding extends Omit<ReportData["findings"][number], "evidence_steps"> {
  evidence_steps: string[];
}

const SEVERITY_COLORS: Record<string, string> = {
  critical: "#dc2626",
  high: "#ea580c",
  medium: "#d97706",
  low: "#65a30d",
};

const SEVERITY_BG: Record<string, string> = {
  critical: "#fef2f2",
  high: "#fff7ed",
  medium: "#fffbeb",
  low: "#f7fee7",
};

export function generateHtmlReport(
  scanId: string,
  targetUrl: string,
  reportJson: string,
  storedFindings: StoredFinding[] = []
): string {
  let data: ReportData;
  try {
    data = JSON.parse(reportJson);
  } catch {
    data = {
      summary: { scan_date: new Date().toISOString(), total_findings: 0, critical: 0, high: 0, medium: 0, low: 0 },
      executive_summary: "Report data could not be parsed.",
      findings: [],
      recommendations: [],
    };
  }

  const normalizedFindings = mergeFindingsWithEvidence(data.findings, storedFindings);

  const findingsHtml = normalizedFindings
    .map(
      (f) => `
    <div class="finding" style="border-left: 4px solid ${SEVERITY_COLORS[f.severity] ?? "#666"}; background: ${SEVERITY_BG[f.severity] ?? "#f9f9f9"};">
      <div class="finding-header">
        <span class="finding-id">${f.id}</span>
        <span class="finding-title">${escapeHtml(f.title)}</span>
        <span class="badge" style="background:${SEVERITY_COLORS[f.severity] ?? "#666"}">${f.severity.toUpperCase()}</span>
      </div>
      <div class="finding-body">
        <p><strong>Type:</strong> ${escapeHtml(f.type)}</p>
        <p><strong>Endpoint:</strong> <code>${escapeHtml(f.endpoint)}</code></p>
        <p><strong>Description:</strong> ${escapeHtml(f.description)}</p>
        <p><strong>Evidence (Step-by-step + Explanation):</strong></p>
        <pre>${escapeHtml(formatEvidenceBlock(f))}</pre>
        ${f.payload ? `<p><strong>Payload Used:</strong></p><pre>${escapeHtml(f.payload)}</pre>` : ""}
        ${f.reproduction ? `<p><strong>Reproduction Command:</strong></p><pre>${escapeHtml(f.reproduction)}</pre>` : ""}
        <p><strong>Remediation:</strong> ${escapeHtml(f.remediation)}</p>
        ${f.references?.length ? `<p><strong>References:</strong> ${f.references.map((r) => escapeHtml(r)).join(", ")}</p>` : ""}
      </div>
    </div>`
    )
    .join("");

  const recommendationsHtml = data.recommendations
    .map((r, i) => `<li><strong>${i + 1}.</strong> ${escapeHtml(r)}</li>`)
    .join("");

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>VAPT Report — ${escapeHtml(targetUrl)}</title>
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; background: #f3f4f6; color: #1f2937; line-height: 1.6; }
    .container { max-width: 900px; margin: 0 auto; padding: 2rem; }
    .header { background: #1e293b; color: white; padding: 2rem; border-radius: 12px; margin-bottom: 2rem; }
    .header h1 { font-size: 1.8rem; margin-bottom: 0.5rem; }
    .header .meta { color: #94a3b8; font-size: 0.9rem; }
    .section { background: white; border-radius: 12px; padding: 1.5rem; margin-bottom: 1.5rem; box-shadow: 0 1px 3px rgba(0,0,0,0.1); }
    .section h2 { font-size: 1.2rem; color: #1e293b; border-bottom: 2px solid #e2e8f0; padding-bottom: 0.5rem; margin-bottom: 1rem; }
    .summary-grid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 1rem; }
    .summary-card { text-align: center; padding: 1rem; border-radius: 8px; }
    .summary-card .count { font-size: 2rem; font-weight: bold; }
    .summary-card .label { font-size: 0.8rem; text-transform: uppercase; letter-spacing: 0.05em; }
    .finding { padding: 1.2rem; margin-bottom: 1rem; border-radius: 8px; }
    .finding-header { display: flex; align-items: center; gap: 1rem; margin-bottom: 0.8rem; flex-wrap: wrap; }
    .finding-id { font-family: monospace; background: #e2e8f0; padding: 2px 8px; border-radius: 4px; font-size: 0.85rem; }
    .finding-title { font-weight: 600; flex: 1; }
    .badge { color: white; padding: 2px 10px; border-radius: 20px; font-size: 0.75rem; font-weight: bold; }
    .finding-body p { margin-bottom: 0.5rem; }
    .finding-body pre { background: #1e293b; color: #e2e8f0; padding: 0.8rem; border-radius: 6px; font-size: 0.85rem; overflow-x: auto; margin: 0.5rem 0 1rem; white-space: pre-wrap; word-break: break-all; }
    code { background: #e2e8f0; padding: 2px 6px; border-radius: 4px; font-size: 0.9em; word-break: break-all; }
    ul { padding-left: 1rem; }
    li { margin-bottom: 0.5rem; }
    .steps { list-style: none; padding: 0; margin: 0.5rem 0 1rem; display: flex; flex-direction: column; gap: 8px; counter-reset: step; }
    .steps li { display: flex; gap: 10px; align-items: flex-start; font-size: 0.9rem; color: #374151; line-height: 1.5; }
    .steps li::before { content: counter(step); counter-increment: step; flex-shrink: 0; width: 22px; height: 22px; border-radius: 50%; background: #1e293b; color: white; font-size: 0.7rem; font-weight: 800; display: flex; align-items: center; justify-content: center; margin-top: 1px; }
    .no-findings { text-align: center; color: #64748b; padding: 2rem; }
  </style>
</head>
<body>
  <div class="container">
    <div class="header">
      <h1>Security Assessment Report</h1>
      <div class="meta">
        <div>Target: ${escapeHtml(targetUrl)}</div>
        <div>Scan ID: ${escapeHtml(scanId)}</div>
        <div>Date: ${new Date(data.summary.scan_date).toLocaleString()}</div>
        <div>Template: Evidence-v2 (step-by-step + explanation)</div>
      </div>
    </div>

    <div class="section">
      <h2>Summary</h2>
      <div class="summary-grid">
        <div class="summary-card" style="background:#fef2f2">
          <div class="count" style="color:#dc2626">${data.summary.critical}</div>
          <div class="label" style="color:#dc2626">Critical</div>
        </div>
        <div class="summary-card" style="background:#fff7ed">
          <div class="count" style="color:#ea580c">${data.summary.high}</div>
          <div class="label" style="color:#ea580c">High</div>
        </div>
        <div class="summary-card" style="background:#fffbeb">
          <div class="count" style="color:#d97706">${data.summary.medium}</div>
          <div class="label" style="color:#d97706">Medium</div>
        </div>
        <div class="summary-card" style="background:#f7fee7">
          <div class="count" style="color:#65a30d">${data.summary.low}</div>
          <div class="label" style="color:#65a30d">Low</div>
        </div>
      </div>
    </div>

    <div class="section">
      <h2>Executive Summary</h2>
      <p>${escapeHtml(data.executive_summary)}</p>
    </div>

    <div class="section">
      <h2>Findings (${normalizedFindings.length})</h2>
      ${normalizedFindings.length > 0 ? findingsHtml : '<div class="no-findings">No vulnerabilities found.</div>'}
    </div>

    <div class="section">
      <h2>Recommendations</h2>
      ${data.recommendations.length > 0
        ? `<ul>${recommendationsHtml}</ul>`
        : "<p>No recommendations.</p>"}
    </div>
  </div>
</body>
</html>`;
}

function mergeFindingsWithEvidence(
  reportFindings: ReportData["findings"],
  storedFindings: StoredFinding[]
): NormalizedFinding[] {
  const byId = new Map(storedFindings.map((f) => [f.id, f]));
  const usedStoredIds = new Set<string>();

  return reportFindings.map((rf) => {
    let sf: StoredFinding | undefined = byId.get(rf.id);
    if (!sf) {
      sf = storedFindings.find(
        (f) => !usedStoredIds.has(f.id) && f.type === rf.type && f.endpoint === rf.endpoint
      );
    }
    if (!sf) {
      sf = storedFindings.find((f) => !usedStoredIds.has(f.id) && f.endpoint === rf.endpoint);
    }
    if (sf) usedStoredIds.add(sf.id);

    const evidenceRaw = rf.evidence ?? sf?.evidence ?? null;
    const payload = rf.payload ?? sf?.payload ?? null;
    const reproduction = rf.reproduction ?? sf?.reproduction ?? null;
    const stepsRaw = rf.evidence_steps?.length ? rf.evidence_steps : sf?.evidence_steps;
    const evidenceSteps = normalizeReportSteps(stepsRaw, rf.type, rf.endpoint, payload, evidenceRaw);
    const evidence = buildEvidenceNarrative(rf.type, evidenceRaw, evidenceSteps);

    return {
      ...rf,
      evidence,
      payload,
      reproduction,
      evidence_steps: evidenceSteps,
    };
  });
}

function normalizeReportSteps(
  steps: string[] | null | undefined,
  type: string,
  endpoint: string,
  payload: string | null,
  evidence: string | null
): string[] {
  if (steps && steps.length > 0) {
    const normalized = steps.map((s, i) => {
      const text = String(s ?? "").trim();
      if (!text) return `Step ${i + 1}: (no detail provided)`;
      return /^step\s*\d+:/i.test(text) ? text : `Step ${i + 1}: ${text}`;
    });
    if (normalized.length >= 4) return normalized;
    return addMissingContextSteps(normalized, type, endpoint, payload, evidence);
  }

  if (type === "header") {
    return [
      `Step 1: Run: curl -i '${endpoint}'. This captures status line and response headers exactly as a browser receives them.`,
      "Step 2: Check whether Strict-Transport-Security is missing from the response headers.",
      `Step 3: Confirm observed behavior: ${evidence ?? "the expected hardening header is absent or weak in the response"}.`,
      "Step 4: Why this matters: without strict HTTPS enforcement, users can be forced onto insecure HTTP in downgrade/SSL-stripping scenarios.",
    ];
  }

  if (type === "file_exposure") {
    return [
      `Step 1: Request the suspected file directly: curl -i '${endpoint}'.`,
      `Step 2: Use the exact discovered probe/path: ${payload ?? "path from reconnaissance output"}.`,
      `Step 3: Confirm the response includes sensitive content or metadata: ${evidence ?? "resource is accessible without proper access control"}.`,
      "Step 4: Why this matters: unauthenticated users can retrieve internal files/configuration and pivot to deeper compromise.",
    ];
  }

  return [
    `Step 1: Prepare a baseline request to ${endpoint} so you can compare normal vs attack behavior.`,
    `Step 2: Send the attack input/probe exactly as shown: ${payload ?? "payload not provided by the model"}.`,
    `Step 3: Confirm the observed behavior: ${evidence ?? "exact response details were not included by the model"}.`,
    `Step 4: Why this confirms exploitability: the application behavior changes in response to untrusted input in a security-sensitive way.`,
  ];
}

function addMissingContextSteps(
  current: string[],
  type: string,
  endpoint: string,
  payload: string | null,
  evidence: string | null
): string[] {
  const fallback = normalizeReportSteps(null, type, endpoint, payload, evidence);
  const merged = [...current];
  for (let i = merged.length; i < 4; i += 1) {
    merged.push(fallback[i]);
  }
  return merged;
}

function buildEvidenceNarrative(
  type: string,
  evidence: string | null,
  steps: string[]
): string {
  const existing = evidence?.trim() ?? "";
  if (/reproduction steps:/i.test(existing) && /what is happening:/i.test(existing)) {
    return existing;
  }

  const stepsText = steps
    .map((s) => s.replace(/^step\s*\d+:\s*/i, "").trim())
    .filter(Boolean)
    .map((s, i) => `${i + 1}. ${s}`)
    .join("\n");
  const observed = existing || "Specific response evidence was not provided by the model.";

  return [
    "Reproduction Steps:",
    stepsText || "1. (no reproduction steps were provided)",
    "",
    "What Is Happening:",
    explainVulnerability(type),
    "",
    "Observed Proof:",
    observed,
  ].join("\n");
}

function formatEvidenceBlock(f: NormalizedFinding): string {
  const stepsText = f.evidence_steps
    .map((s) => s.replace(/^step\s*\d+:\s*/i, "").trim())
    .filter(Boolean)
    .map((s, i) => `${i + 1}. ${s}`)
    .join("\n");

  const observed = f.evidence?.trim() || "Specific response evidence was not provided by the model.";
  const explanation = explainVulnerability(f.type);
  return [
    "Reproduction Steps:",
    stepsText || "1. (no reproduction steps were provided)",
    "",
    "What Is Happening:",
    explanation,
    "",
    "Observed Proof:",
    observed,
  ].join("\n");
}

function explainVulnerability(type: string): string {
  if (type === "sqli") {
    return "SQL injection happens when input is concatenated into SQL queries, allowing attackers to alter database logic.";
  }
  if (type === "xss") {
    return "XSS happens when untrusted input is returned to the browser without safe encoding, enabling attacker-controlled script execution.";
  }
  if (type === "header") {
    return "Header disclosure reveals implementation/version details that improve attacker reconnaissance and vulnerability matching.";
  }
  if (type === "file_exposure") {
    return "File exposure happens when sensitive files or backup artifacts are directly reachable over HTTP.";
  }
  return "This finding exposes behavior that increases attack surface and should be remediated.";
}

function escapeHtml(str: string | null | undefined): string {
  if (!str) return "";
  return str
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/\"/g, "&quot;")
    .replace(/'/g, "&#039;");
}
