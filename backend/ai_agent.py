import os
import json
import logging
import uuid
from openai import OpenAI
from models import (
    VulnFinding, PTResult, ReportNarrative, Severity,
    ScanSession, AgentStatus, STRIDEThreat, ThreatModel, SASTFinding,
)

logger = logging.getLogger(__name__)
OPENAI_MODEL = os.getenv("OPENAI_MODEL", "gpt-4o")
client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))


def _call(messages: list[dict], tool: dict) -> dict:
    response = client.chat.completions.create(
        model=OPENAI_MODEL,
        messages=messages,
        tools=[tool],
        tool_choice={"type": "function", "function": {"name": tool["function"]["name"]}},
        temperature=0.2,
    )
    return json.loads(response.choices[0].message.tool_calls[0].function.arguments)


# ═══════════════════════════════════════════════════════════════════════════
# DESIGN PHASE — STRIDE Threat Modeling
# ═══════════════════════════════════════════════════════════════════════════

THREAT_MODEL_TOOL = {
    "type": "function",
    "function": {
        "name": "return_threat_model",
        "description": "Return a STRIDE threat model for the described application.",
        "parameters": {
            "type": "object",
            "properties": {
                "threats": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "category": {"type": "string", "enum": ["Spoofing","Tampering","Repudiation","Information Disclosure","Denial of Service","Elevation of Privilege"]},
                            "threat": {"type": "string"},
                            "attack_vector": {"type": "string"},
                            "impact": {"type": "string"},
                            "mitigation": {"type": "string"},
                            "risk_level": {"type": "string", "enum": ["Critical","High","Medium","Low"]},
                        },
                        "required": ["category","threat","attack_vector","impact","mitigation","risk_level"],
                    },
                },
                "summary": {"type": "string"},
                "top_risks": {"type": "array", "items": {"type": "string"}},
            },
            "required": ["threats","summary","top_risks"],
        },
    },
}


def generate_threat_model(app_name: str, app_description: str) -> ThreatModel:
    messages = [
        {
            "role": "system",
            "content": (
                "You are a Principal Security Architect specialising in STRIDE threat modeling. "
                "Analyse the application description and identify realistic security threats "
                "across all six STRIDE categories. For each threat provide a concrete attack vector, "
                "business impact, and actionable mitigation. Be specific, not generic."
            ),
        },
        {
            "role": "user",
            "content": f"Application: {app_name}\n\nDescription: {app_description}\n\nGenerate a complete STRIDE threat model.",
        },
    ]
    result = _call(messages, THREAT_MODEL_TOOL)
    threats = [
        STRIDEThreat(id=str(uuid.uuid4()), **t)
        for t in result.get("threats", [])
    ]
    logger.info("Codex generated %d STRIDE threats for %s", len(threats), app_name)
    return ThreatModel(
        app_name=app_name,
        app_description=app_description,
        threats=threats,
        summary=result.get("summary", ""),
        top_risks=result.get("top_risks", []),
    )


# ═══════════════════════════════════════════════════════════════════════════
# DEVELOPMENT PHASE — SAST Code Analysis
# ═══════════════════════════════════════════════════════════════════════════

SAST_TOOL = {
    "type": "function",
    "function": {
        "name": "return_sast_findings",
        "description": "Return SAST findings from static code analysis.",
        "parameters": {
            "type": "object",
            "properties": {
                "findings": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "name": {"type": "string"},
                            "severity": {"type": "string", "enum": ["Critical","High","Medium","Low","Informational"]},
                            "file_path": {"type": "string"},
                            "line": {"type": "integer"},
                            "description": {"type": "string"},
                            "ai_explanation": {"type": "string"},
                            "cwe": {"type": "string"},
                            "fix": {"type": "string"},
                            "confidence": {"type": "number"},
                        },
                        "required": ["name","severity","description","ai_explanation","confidence"],
                    },
                },
            },
            "required": ["findings"],
        },
    },
}


def analyze_code_sast(code_snippet: str, file_context: str = "") -> list[SASTFinding]:
    ctx = f"\nFile context: {file_context}" if file_context else ""
    messages = [
        {
            "role": "system",
            "content": (
                "You are a Senior Application Security Engineer performing static code analysis. "
                "Identify real security vulnerabilities — injection flaws, insecure crypto, "
                "hardcoded secrets, broken auth, IDOR, SSRF, path traversal, etc. "
                "Assign a confidence score (0.0–1.0) reflecting certainty. "
                "Do NOT flag style issues or non-security concerns."
            ),
        },
        {
            "role": "user",
            "content": f"Analyse this code for security vulnerabilities:{ctx}\n\n```\n{code_snippet}\n```",
        },
    ]
    result = _call(messages, SAST_TOOL)
    findings = []
    for item in result.get("findings", []):
        findings.append(SASTFinding(
            id=str(uuid.uuid4()),
            name=item["name"],
            severity=Severity(item["severity"]),
            file_path=item.get("file_path"),
            line=item.get("line"),
            description=item["description"],
            ai_explanation=item["ai_explanation"],
            cwe=item.get("cwe"),
            fix=item.get("fix"),
            confidence=item.get("confidence", 0.8),
        ))
    logger.info("Codex SAST found %d findings", len(findings))
    return findings


# ═══════════════════════════════════════════════════════════════════════════
# DEPLOYMENT PHASE — VA Analysis (ZAP alerts → structured findings)
# ═══════════════════════════════════════════════════════════════════════════

VA_TOOL = {
    "type": "function",
    "function": {
        "name": "return_analyzed_findings",
        "description": "Return structured VA findings with confidence scores from ZAP alerts.",
        "parameters": {
            "type": "object",
            "properties": {
                "findings": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "name": {"type": "string"},
                            "severity": {"type": "string", "enum": ["Critical","High","Medium","Low","Informational"]},
                            "url": {"type": "string"},
                            "description": {"type": "string"},
                            "ai_explanation": {"type": "string"},
                            "cwe": {"type": "string"},
                            "cvss": {"type": "number"},
                            "solution": {"type": "string"},
                            "pt_category": {"type": "string"},
                            "confidence": {"type": "number", "description": "0.0-1.0 confidence this is a real finding"},
                        },
                        "required": ["name","severity","url","description","ai_explanation","confidence"],
                    },
                },
            },
            "required": ["findings"],
        },
    },
}


def analyze_zap_alerts(raw_alerts: list[dict]) -> list[VulnFinding]:
    alerts_summary = json.dumps(raw_alerts[:50], indent=2)
    messages = [
        {
            "role": "system",
            "content": (
                "You are an expert security analyst. Analyze OWASP ZAP alerts, deduplicate "
                "by vulnerability name (keep most severe instance), and return structured findings. "
                "Assign a confidence score (0.0–1.0) for each finding — passive scan findings "
                "are typically 0.5–0.8 confidence. Write ai_explanation in plain English for "
                "a non-technical business audience."
            ),
        },
        {"role": "user", "content": f"Analyze these ZAP VA alerts:\n\n{alerts_summary}"},
    ]
    result = _call(messages, VA_TOOL)
    findings = []
    for item in result.get("findings", []):
        findings.append(VulnFinding(
            id=str(uuid.uuid4()),
            name=item["name"],
            severity=Severity(item["severity"]),
            url=item["url"],
            description=item["description"],
            ai_explanation=item["ai_explanation"],
            cwe=item.get("cwe"),
            cvss=item.get("cvss"),
            solution=item.get("solution"),
            pt_category=item.get("pt_category"),
            confidence=item.get("confidence", 0.7),
        ))
    logger.info("Codex analyzed %d findings from %d raw alerts", len(findings), len(raw_alerts))
    return findings


# ═══════════════════════════════════════════════════════════════════════════
# DEPLOYMENT PHASE — PT: one agent per vulnerability
# ═══════════════════════════════════════════════════════════════════════════

VERIFY_TOOL = {
    "type": "function",
    "function": {
        "name": "return_pt_verification",
        "description": "Return PT verdict for ONE specific vulnerability.",
        "parameters": {
            "type": "object",
            "properties": {
                "finding_id": {"type": "string"},
                "status": {"type": "string", "enum": ["confirmed","false_positive","inconclusive"]},
                "evidence": {"type": "string"},
                "explanation": {"type": "string"},
                "attack_vector": {"type": "string"},
                "confidence": {"type": "number"},
                "attack_walkthrough": {
                    "type": "string",
                    "description": (
                        "An educational step-by-step explanation of how this vulnerability was "
                        "discovered and confirmed during penetration testing. Format as numbered steps. "
                        "Include: (1) what technique/payload was used, (2) what the scanner sent to the server, "
                        "(3) what response revealed the vulnerability, (4) real-world impact in plain English, "
                        "(5) how a defender would detect and prevent this attack. "
                        "Write for a developer who wants to understand security testing."
                    ),
                },
            },
            "required": ["finding_id","status","explanation","confidence","attack_walkthrough"],
        },
    },
}


def run_single_pt_agent(
    finding: VulnFinding,
    pt_alerts: list[dict],
    agent_status: AgentStatus,
    update_fn,
) -> PTResult:
    agent_status.status = "running"
    agent_status.log = f"Analysing evidence for {finding.name}…"
    update_fn(agent_status)

    relevant = [
        a for a in pt_alerts
        if finding.url in a.get("url", "") or finding.name.lower() in a.get("alert", "").lower()
    ]
    if not relevant:
        relevant = pt_alerts[:20]

    messages = [
        {
            "role": "system",
            "content": (
                f"You are a dedicated penetration testing agent assigned to verify ONE vulnerability:\n\n"
                f"Name: {finding.name}\nSeverity: {finding.severity}\nURL: {finding.url}\n"
                f"Description: {finding.description}\n\n"
                "Analyse the active scan evidence. If confirmed with clear evidence → confirmed. "
                "If no supporting evidence → false_positive. If ambiguous → inconclusive. "
                "Provide a confidence score 0.0–1.0.\n\n"
                "Also write an educational attack_walkthrough explaining step-by-step how this "
                "vulnerability was found and what it means. Target audience: developers learning "
                "about security testing. Use numbered steps. Be specific and concrete."
            ),
        },
        {
            "role": "user",
            "content": (
                f"Active scan evidence:\n{json.dumps(relevant[:20], indent=2)}\n\n"
                f"Finding ID: {finding.id}"
            ),
        },
    ]

    try:
        result = _call(messages, VERIFY_TOOL)
        pt_result = PTResult(
            finding_id=finding.id,
            status=result["status"],
            evidence=result.get("evidence"),
            explanation=result["explanation"],
            attack_vector=result.get("attack_vector"),
            attack_walkthrough=result.get("attack_walkthrough"),
        )
        agent_status.status = "complete"
        agent_status.verdict = result["status"]
        agent_status.log = f"Verdict: {result['status'].replace('_',' ').title()} (confidence: {result.get('confidence',0):.0%})"
        update_fn(agent_status)
        return pt_result
    except Exception as exc:
        logger.exception("Agent %s failed", agent_status.agent_id)
        agent_status.status = "error"
        agent_status.log = f"Error: {exc}"
        update_fn(agent_status)
        return PTResult(finding_id=finding.id, status="inconclusive", explanation=str(exc))


# ═══════════════════════════════════════════════════════════════════════════
# REPORT NARRATIVE
# ═══════════════════════════════════════════════════════════════════════════

NARRATIVE_TOOL = {
    "type": "function",
    "function": {
        "name": "return_report_narrative",
        "description": "Return executive summary and recommendations.",
        "parameters": {
            "type": "object",
            "properties": {
                "executive_summary": {"type": "string"},
                "risk_rating": {"type": "string", "enum": ["Critical","High","Medium","Low"]},
                "key_findings": {"type": "array", "items": {"type": "string"}},
                "recommendations": {"type": "array", "items": {"type": "string"}},
            },
            "required": ["executive_summary","risk_rating","key_findings","recommendations"],
        },
    },
}


def generate_report_narrative(session: ScanSession) -> ReportNarrative:
    summary = {
        "phase": session.phase,
        "target": session.target_url or session.threat_model.app_name if session.threat_model else "N/A",
        "va_findings": [{"name": f.name, "severity": f.severity, "confidence": f.confidence} for f in session.va_findings],
        "sast_findings": [{"name": f.name, "severity": f.severity} for f in session.sast_findings],
        "pt_results": [{"status": r.status, "explanation": r.explanation} for r in session.pt_results],
    }
    messages = [
        {
            "role": "system",
            "content": (
                "You are a senior security consultant writing a professional VAPT report. "
                "Write a concise executive summary and actionable recommendations. "
                "Audience is a mix of technical and non-technical stakeholders."
            ),
        },
        {"role": "user", "content": f"Generate report narrative:\n{json.dumps(summary, indent=2)}"},
    ]
    result = _call(messages, NARRATIVE_TOOL)
    return ReportNarrative(
        executive_summary=result["executive_summary"],
        risk_rating=result["risk_rating"],
        key_findings=result.get("key_findings", []),
        recommendations=result.get("recommendations", []),
    )
