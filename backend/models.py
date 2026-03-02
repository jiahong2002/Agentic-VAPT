from pydantic import BaseModel
from typing import Optional
from enum import Enum


class SASTConfig(BaseModel):
    repo_url: str
    pat: Optional[str] = None


class ScanRequest(BaseModel):
    url: str
    sast_config: Optional[SASTConfig] = None
    deep_scan: bool = False


class ScanStatus(str, Enum):
    CRAWLING = "CRAWLING"
    SCANNING = "SCANNING"
    SAST_CLONING = "SAST_CLONING"
    SAST_ANALYZING = "SAST_ANALYZING"
    AWAITING_APPROVAL = "AWAITING_APPROVAL"
    EXPLOITING = "EXPLOITING"
    DONE = "DONE"
    ERROR = "ERROR"


class AgentStatus(str, Enum):
    PENDING = "PENDING"
    RUNNING = "RUNNING"
    CONFIRMED = "CONFIRMED"
    UNCONFIRMED = "UNCONFIRMED"
    ERROR = "ERROR"


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class Hypothesis(BaseModel):
    id: str
    title: str
    target_url: str = ""
    attack_surface: str
    technique: str
    attack_hints: str = ""   # guidance for the agent — what to focus on, NOT a specific payload
    rationale: str
    severity_estimate: Severity = Severity.MEDIUM


class SurfaceReport(BaseModel):
    target_url: str
    discovered_urls: list[str] = []
    forms: list[dict] = []
    cookies: list[dict] = []
    headers: dict = {}
    tech_stack: list[str] = []
    js_endpoints: list[str] = []
    open_ports: list[int] = []
    notes: list[str] = []
    scanner_findings: list[dict] = []  # Nuclei active scanner results


class ExploitStep(BaseModel):
    step_number: int
    description: str
    action: str
    screenshot_path: Optional[str] = None
    response_evidence: Optional[str] = None


class AgentResult(BaseModel):
    hypothesis_id: str
    hypothesis_title: str
    technique: str
    status: AgentStatus
    severity: Severity
    steps: list[ExploitStep] = []
    summary: str = ""
    remediation: str = ""
    cvss_score: Optional[float] = None
    screenshot_paths: list[str] = []
    false_positive_reason: Optional[str] = None


class CodeFinding(BaseModel):
    tool: str  # "semgrep" | "npm_audit"
    rule_id: str
    severity: Severity
    file_path: str
    line_number: Optional[int] = None
    message: str
    code_snippet: Optional[str] = None


class ScanState(BaseModel):
    scan_id: str
    user_id: str = ""
    target_url: str
    status: ScanStatus = ScanStatus.CRAWLING
    deep_scan: bool = False
    surface_report: Optional[SurfaceReport] = None
    hypotheses: list[Hypothesis] = []
    agent_results: list[AgentResult] = []
    sast_config: Optional[SASTConfig] = None
    sast_findings: list[CodeFinding] = []
    error: Optional[str] = None
