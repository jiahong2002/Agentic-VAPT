from pydantic import BaseModel
from typing import Optional
from enum import Enum


class ScanState(str, Enum):
    IDLE = "IDLE"
    RUNNING = "RUNNING"
    COMPLETE = "COMPLETE"
    AWAITING_GREENLIGHT = "AWAITING_GREENLIGHT"
    GREENLIGHTED = "GREENLIGHTED"
    PT_RUNNING = "PT_RUNNING"
    REPORT_READY = "REPORT_READY"
    ERROR = "ERROR"


class SDLCPhase(str, Enum):
    DESIGN = "design"
    DEVELOPMENT = "development"
    DEPLOYMENT = "deployment"


class Severity(str, Enum):
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFO = "Informational"


# ── Design Phase ──────────────────────────────────────────────────────────

class STRIDEThreat(BaseModel):
    id: str
    category: str        # Spoofing | Tampering | Repudiation | Information Disclosure | DoS | Elevation
    threat: str
    attack_vector: str
    impact: str
    mitigation: str
    risk_level: str      # Critical | High | Medium | Low


class ThreatModel(BaseModel):
    app_name: str
    app_description: str
    threats: list[STRIDEThreat] = []
    summary: str = ""
    top_risks: list[str] = []


# ── Development Phase ─────────────────────────────────────────────────────

class SASTFinding(BaseModel):
    id: str
    name: str
    severity: Severity
    file_path: Optional[str] = None
    line: Optional[int] = None
    description: str
    ai_explanation: str
    cwe: Optional[str] = None
    fix: Optional[str] = None
    confidence: float = 0.8   # 0.0–1.0


# ── Deployment Phase ──────────────────────────────────────────────────────

class VulnFinding(BaseModel):
    id: str
    name: str
    severity: Severity
    url: str
    description: str
    ai_explanation: str
    cwe: Optional[str] = None
    cvss: Optional[float] = None
    evidence: Optional[str] = None
    solution: Optional[str] = None
    pt_category: Optional[str] = None
    confidence: float = 0.8   # 0.0–1.0


class AgentStatus(BaseModel):
    agent_id: str
    finding_id: str
    finding_name: str
    severity: str
    status: str = "pending"   # pending | running | complete | error
    verdict: Optional[str] = None
    log: Optional[str] = None


class PTResult(BaseModel):
    finding_id: str
    status: str           # confirmed | false_positive | inconclusive
    evidence: Optional[str] = None
    explanation: str
    attack_vector: Optional[str] = None
    attack_walkthrough: Optional[str] = None   # step-by-step educational explanation


class ReportNarrative(BaseModel):
    executive_summary: str
    risk_rating: str
    key_findings: list[str]
    recommendations: list[str]


# ── Audit ─────────────────────────────────────────────────────────────────

class AuditEntry(BaseModel):
    timestamp: str
    event: str            # scan_started | va_complete | greenlight_approved | pt_started | report_ready | etc.
    actor: str            # "system" | user-supplied name
    detail: str
    phase: Optional[str] = None


# ── Session ───────────────────────────────────────────────────────────────

class ScanSession(BaseModel):
    session_id: str
    phase: SDLCPhase = SDLCPhase.DEPLOYMENT
    state: ScanState = ScanState.IDLE

    # Initiator / approver (4-eyes governance)
    initiated_by: str = "anonymous"
    greenlighted_by: Optional[str] = None

    # Design phase
    threat_model: Optional[ThreatModel] = None

    # Development phase
    code_snippet: Optional[str] = None
    sast_findings: list[SASTFinding] = []

    # Deployment phase
    target_url: Optional[str] = None
    zap_scan_id: Optional[str] = None
    zap_spider_id: Optional[str] = None
    va_findings: list[VulnFinding] = []
    approved_finding_ids: list[str] = []
    reviewed_finding_ids: list[str] = []   # tracks individual review (anti-rubber-stamp)
    pt_results: list[PTResult] = []
    agent_statuses: list[AgentStatus] = []
    narrative: Optional[ReportNarrative] = None

    # Common
    error_message: Optional[str] = None
    start_time: Optional[str] = None
    end_time: Optional[str] = None
    audit_log: list[AuditEntry] = []
    progress_log: list[str] = []   # live scan progress messages
    spider_progress: int = 0       # 0-100 for ZAP spider
    scan_progress: int = 0         # 0-100 for ZAP active scan


# ── Request Bodies ─────────────────────────────────────────────────────────

class StartDeploymentScan(BaseModel):
    url: str
    initiated_by: str = "Security Engineer"


class StartDesignScan(BaseModel):
    app_name: str
    app_description: str
    initiated_by: str = "Security Architect"


class StartDevScan(BaseModel):
    code_snippet: str
    file_context: Optional[str] = None
    initiated_by: str = "Developer"


class GreenlightRequest(BaseModel):
    approved_finding_ids: list[str]
    greenlighted_by: str
    risk_acknowledgement: bool   # must be True


class ReviewFindingRequest(BaseModel):
    finding_id: str
    reviewer: str
