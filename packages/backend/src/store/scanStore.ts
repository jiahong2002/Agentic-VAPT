import type { ApprovalGate } from "../agent/approvalGate.js";

export type ScanPhase = "recon" | "exploit" | "report" | "complete" | "error";
export type ScanStatus = "running" | "awaiting_approval" | "complete" | "error";

export interface Finding {
  id: string;
  type: "sqli" | "xss" | "file_exposure" | "header";
  title: string;
  severity: "critical" | "high" | "medium" | "low";
  endpoint: string;
  description: string;
  evidence: string | null;
  evidence_steps: string[] | null;
  payload: string | null;
  reproduction: string | null;
  remediation: string;
}

export interface ExploitCandidate {
  type: "sqli" | "xss" | "file_exposure" | "header";
  endpoint: string;
  param: string;
  method: string;
  description: string;
  priority: "high" | "medium" | "low";
}

export interface ScanState {
  id: string;
  url: string;
  status: ScanStatus;
  phase: ScanPhase;
  gate: ApprovalGate | null;
  findings: Finding[];
  reconResult: string | null;
  exploitResults: string | null;
  report: string | null;
  createdAt: Date;
  error: string | null;
}

const store = new Map<string, ScanState>();

export const ScanStore = {
  create(id: string, url: string): ScanState {
    const state: ScanState = {
      id,
      url,
      status: "running",
      phase: "recon",
      gate: null,
      findings: [],
      reconResult: null,
      exploitResults: null,
      report: null,
      createdAt: new Date(),
      error: null,
    };
    store.set(id, state);
    return state;
  },

  get(id: string): ScanState | undefined {
    return store.get(id);
  },

  update(id: string, patch: Partial<ScanState>): void {
    const existing = store.get(id);
    if (existing) {
      store.set(id, { ...existing, ...patch });
    }
  },

  addFinding(id: string, finding: Finding): void {
    const existing = store.get(id);
    if (existing) {
      existing.findings.push(finding);
    }
  },
};
