import json
import uuid
from openai import AsyncOpenAI
from models import Hypothesis, SurfaceReport, Severity
from pipeline.scanner import build_surface_notes
from dotenv import load_dotenv

load_dotenv()

_client: AsyncOpenAI | None = None

def _get_client() -> AsyncOpenAI:
    global _client
    if _client is None:
        _client = AsyncOpenAI(max_retries=6)
    return _client

RECON_SYSTEM_PROMPT = """You are a security analyst reviewing a web application's attack surface.

Your task: identify which vulnerability CLASSES are worth investigating, and for each one create an investigation assignment for a dedicated exploit agent.

## Critical rule — one assignment per vulnerability class
Do NOT create one assignment per parameter or per URL.
Create ONE assignment per vulnerability class (e.g. one for "SQL Injection", one for "XSS").
The exploit agent assigned to each class is smart: it will form its own specific attack hypothesis,
test it, and revise if it fails. Your job is only to tell it WHERE to look and WHY.

## Vulnerability classes to consider
INJECTION: SQL Injection, Reflected Cross-Site Scripting, Server-Side Template Injection, Command Injection, Path Traversal, XXE
ACCESS CONTROL: IDOR, Default Credentials, Broken Access Control
SERVER-SIDE: SSRF, Open Redirect, CORS Misconfiguration
INFORMATION DISCLOSURE: Exposed Sensitive Files, API Documentation Exposure, Security Header Misconfiguration
OTHER: Prototype Pollution, CSRF, File Upload Vulnerabilities

## For each investigation assignment provide:
- title: e.g. "SQL Injection Investigation"
- target_url: the single best URL to start from (the one most likely to have this vulnerability)
- attack_surface: comma-separated list of ALL candidate attack points for this class
  (include multiple URLs and parameters if applicable)
- technique: MUST be one of these exact strings:
    "Reflected Cross-Site Scripting", "SQL Injection", "Server-Side Template Injection",
    "Command Injection", "Path Traversal", "SSRF", "Open Redirect", "CORS Misconfiguration",
    "Exposed Sensitive Files", "API Documentation Exposure", "Default Credentials", "IDOR",
    "Broken Access Control", "Security Header Misconfiguration", "File Upload Vulnerabilities",
    "Prototype Pollution", "CSRF"
- attack_hints: context to guide the agent — what tech is in use, what forms/params look interesting,
  which variant of this technique is most likely. Do NOT prescribe exact payloads.
- rationale: 1-2 sentences on why this class applies to this specific application
- severity_estimate: CRITICAL / HIGH / MEDIUM / LOW / INFO

## Output format
Respond with ONLY valid JSON:
{
  "hypotheses": [
    {
      "title": "SQL Injection Investigation",
      "target_url": "http://target/login.php",
      "attack_surface": "POST /login.php (username, password fields), GET /vulnerabilities/sqli/ (id param), any other forms accepting user input",
      "technique": "SQL Injection",
      "attack_hints": "PHP/MySQL backend detected. Login form likely uses unsanitised query. Also check search/lookup forms. Try error-based, boolean-blind, and data extraction vectors. Auth bypass is high-value target.",
      "rationale": "Multiple user-input forms found against a PHP/MySQL backend — classic SQLi target.",
      "severity_estimate": "CRITICAL"
    }
  ]
}

`target_url` MUST be the exact full URL from the surface report (e.g. "http://localhost/vulnerabilities/sqli/"). Use the base URL only if no specific sub-page applies.

Generate 5–10 investigation assignments covering the most applicable classes.
Order by severity (highest first).
"""


async def run_recon_agent(surface: SurfaceReport) -> list[Hypothesis]:
    """Run the Recon Agent to generate per-technique investigation assignments."""
    surface_summary = build_surface_notes(surface)

    response = await _get_client().chat.completions.create(
        model="gpt-4o",
        messages=[
            {"role": "system", "content": RECON_SYSTEM_PROMPT},
            {"role": "user", "content": f"Here is the surface report:\n\n{surface_summary}"},
        ],
        response_format={"type": "json_object"},
    )

    content = response.choices[0].message.content
    data = json.loads(content)

    hypotheses = []
    for h in data.get("hypotheses", []):
        try:
            severity = Severity(h.get("severity_estimate", "MEDIUM"))
        except ValueError:
            severity = Severity.MEDIUM

        hypotheses.append(Hypothesis(
            id=str(uuid.uuid4()),
            title=h.get("title", "Unknown"),
            target_url=h.get("target_url", ""),
            attack_surface=h.get("attack_surface", ""),
            technique=h.get("technique", ""),
            attack_hints=h.get("attack_hints", ""),
            rationale=h.get("rationale", ""),
            severity_estimate=severity,
        ))

    return hypotheses
