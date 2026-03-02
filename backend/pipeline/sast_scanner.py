import asyncio
import json
import os
import logging
from models import CodeFinding, Severity

logger = logging.getLogger(__name__)

SEVERITY_MAP = {
    "error": Severity.CRITICAL,
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "warning": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
    "info": Severity.INFO,
    "informational": Severity.INFO,
}


async def run_semgrep(repo_path: str) -> list[CodeFinding]:
    """Run semgrep --config=auto on the repo. Returns list[CodeFinding]."""
    try:
        proc = await asyncio.create_subprocess_exec(
            "semgrep", "--config=auto", "--json", "--quiet", repo_path,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=180)
    except FileNotFoundError:
        logger.warning("semgrep not installed — skipping")
        return []
    except asyncio.TimeoutError:
        proc.kill()
        logger.warning("semgrep timed out — skipping")
        return []

    findings = []
    try:
        data = json.loads(stdout)
        for r in data.get("results", []):
            sev_str = r.get("extra", {}).get("severity", "info").lower()
            severity = SEVERITY_MAP.get(sev_str, Severity.INFO)

            file_path = r.get("path", "")
            if file_path.startswith(repo_path):
                file_path = file_path[len(repo_path):].lstrip("/\\")

            findings.append(CodeFinding(
                tool="semgrep",
                rule_id=r.get("check_id", "unknown"),
                severity=severity,
                file_path=file_path,
                line_number=r.get("start", {}).get("line"),
                message=r.get("extra", {}).get("message", ""),
                code_snippet=r.get("extra", {}).get("lines", ""),
            ))
    except (json.JSONDecodeError, KeyError) as e:
        logger.warning(f"semgrep JSON parse error: {e}")

    logger.info(f"semgrep found {len(findings)} issues")
    return findings


async def run_npm_audit(repo_path: str) -> list[CodeFinding]:
    """Run npm audit --json in the repo dir if package.json exists."""
    pkg_json = os.path.join(repo_path, "package.json")
    if not os.path.exists(pkg_json):
        logger.info("No package.json found — skipping npm audit")
        return []

    try:
        proc = await asyncio.create_subprocess_exec(
            "npm", "audit", "--json",
            cwd=repo_path,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=60)
    except FileNotFoundError:
        logger.warning("npm not found — skipping npm audit")
        return []
    except asyncio.TimeoutError:
        proc.kill()
        logger.warning("npm audit timed out — skipping")
        return []

    findings = []
    try:
        data = json.loads(stdout)
        # npm audit v7+ uses "vulnerabilities" dict
        for pkg_name, vuln in data.get("vulnerabilities", {}).items():
            sev_str = vuln.get("severity", "info").lower()
            severity = SEVERITY_MAP.get(sev_str, Severity.INFO)

            via = vuln.get("via", [])
            messages = [v.get("title") or v.get("url", "") for v in via if isinstance(v, dict)]
            message = "; ".join(m for m in messages if m) or f"Vulnerable dependency: {pkg_name}"

            findings.append(CodeFinding(
                tool="npm_audit",
                rule_id=f"npm:{pkg_name}",
                severity=severity,
                file_path="package.json",
                line_number=None,
                message=message,
                code_snippet=f"{pkg_name}@{vuln.get('range', 'unknown')}",
            ))
    except (json.JSONDecodeError, KeyError) as e:
        logger.warning(f"npm audit JSON parse error: {e}")

    logger.info(f"npm audit found {len(findings)} vulnerabilities")
    return findings


async def run_sast(repo_path: str) -> list[CodeFinding]:
    """Run all SAST tools concurrently and return merged findings."""
    semgrep_findings, npm_findings = await asyncio.gather(
        run_semgrep(repo_path),
        run_npm_audit(repo_path),
    )
    return semgrep_findings + npm_findings
