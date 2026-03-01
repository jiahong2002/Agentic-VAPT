import axios from "axios";

const BASE = "http://localhost:8000";

// ── Design Phase ──────────────────────────────────────────────────────────
export const startDesignScan = (body) =>
  axios.post(`${BASE}/api/design/start`, body).then((r) => r.data);

// ── Development Phase ─────────────────────────────────────────────────────
export const startDevScan = (body) =>
  axios.post(`${BASE}/api/development/start`, body).then((r) => r.data);

// ── Deployment Phase ──────────────────────────────────────────────────────
export const startDeploymentScan = (body) =>
  axios.post(`${BASE}/api/deployment/start`, body).then((r) => r.data);

// Legacy alias — kept so old code doesn't break
export const startScan = (url) =>
  startDeploymentScan({ url, initiated_by: "Security Engineer" });

// ── Universal ─────────────────────────────────────────────────────────────
export const getStatus = (sessionId) =>
  axios.get(`${BASE}/api/scan/${sessionId}/status`).then((r) => r.data);

export const getResults = (sessionId) =>
  axios.get(`${BASE}/api/scan/${sessionId}/results`).then((r) => r.data);

export const reviewFinding = (sessionId, finding_id, reviewer) =>
  axios
    .post(`${BASE}/api/scan/${sessionId}/review-finding`, { finding_id, reviewer })
    .then((r) => r.data);

export const greenlightScan = (sessionId, body) =>
  axios
    .post(`${BASE}/api/scan/${sessionId}/greenlight`, body)
    .then((r) => r.data);

export const skipPT = (sessionId) =>
  axios.post(`${BASE}/api/scan/${sessionId}/skip-pt`).then((r) => r.data);

export const getAuditLog = (sessionId) =>
  axios.get(`${BASE}/api/scan/${sessionId}/audit-log`).then((r) => r.data);

export const getAgentStatuses = (sessionId) =>
  axios.get(`${BASE}/api/scan/${sessionId}/agent-statuses`).then((r) => r.data);

export const getPTResults = (sessionId) =>
  axios.get(`${BASE}/api/scan/${sessionId}/pt-results`).then((r) => r.data);

// ── Legacy compat (deployment phase old API) ──────────────────────────────
export const getVAResults = (sessionId) =>
  getResults(sessionId).then((d) => ({ findings: d.va_findings }));

export const approvePT = (sessionId, findingIds) =>
  greenlightScan(sessionId, {
    approved_finding_ids: findingIds,
    greenlighted_by: "Security Engineer",
    risk_acknowledgement: true,
  });

// ── Report ────────────────────────────────────────────────────────────────
export const getReportUrl = (sessionId) =>
  `${BASE}/api/scan/${sessionId}/report`;

export const getReportDownloadUrl = (sessionId) =>
  `${BASE}/api/scan/${sessionId}/report/download`;
