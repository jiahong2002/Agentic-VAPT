"""
Active vulnerability scanner integration — uses Nuclei.

Install: brew install nuclei   (macOS)
         or download from https://github.com/projectdiscovery/nuclei/releases

Nuclei runs a curated set of HTTP templates against the target and returns
structured JSON findings. Results are normalised and stored on the SurfaceReport
so the Recon Agent can use them when assigning investigation slots.

If Nuclei is not installed, the function returns an empty list and the pipeline
continues normally without scanner findings.
"""

import asyncio
import json
import shutil
import logging

logger = logging.getLogger(__name__)

# Template categories to run in standard mode
_NUCLEI_TAGS = "misconfig,exposure,default-login,tech,xss,sqli,ssrf,rce,lfi"

# Standard scan timeout
_SCAN_TIMEOUT_SECS = 180
# Deep scan timeout — more templates, needs more time
_SCAN_TIMEOUT_DEEP_SECS = 360


async def run_nuclei(target_url: str, deep: bool = False) -> list[dict]:
    """
    Run Nuclei against target_url and return a list of normalised findings.
    Returns [] if Nuclei is not installed or the scan fails.

    Each finding dict has:
        name        - template name / vulnerability title
        severity    - CRITICAL / HIGH / MEDIUM / LOW / INFO
        url         - the matched URL
        template_id - Nuclei template ID
        description - short description (may be empty)
        tags        - list of category tags
        matcher     - what matched (extracted value or matcher name)
    """
    if not shutil.which("nuclei"):
        logger.info("Nuclei not found in PATH — skipping active scan. Install: brew install nuclei")
        return []

    timeout = _SCAN_TIMEOUT_DEEP_SECS if deep else _SCAN_TIMEOUT_SECS

    cmd = [
        "nuclei",
        "-u", target_url,
        "-json",              # JSONL output to stdout, one finding per line
        "-silent",            # suppress banner/progress to stderr
        "-nc",                # no colour codes
        "-c", "50" if deep else "25",   # more concurrency in deep mode
        "-timeout", "5",      # per-request timeout (seconds)
        "-retries", "1",
        "-exclude-tags", "dos,fuzz,ssl,headless,network,dns",
    ]

    # Standard mode: curated tags only. Deep mode: run all templates.
    if not deep:
        cmd.extend(["-tags", _NUCLEI_TAGS])

    logger.info(f"[Nuclei] Starting {'deep ' if deep else ''}scan: {' '.join(cmd)}")

    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )

        try:
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(), timeout=timeout
            )
        except asyncio.TimeoutError:
            logger.warning(f"[Nuclei] Scan timed out after {_SCAN_TIMEOUT_SECS}s — using partial results")
            proc.kill()
            stdout, _ = await proc.communicate()

        findings = []
        for line in stdout.decode(errors="ignore").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
                info = data.get("info", {})
                findings.append({
                    "name": info.get("name", "Unknown"),
                    "severity": info.get("severity", "info").upper(),
                    "url": data.get("matched-at", target_url),
                    "template_id": data.get("template-id", ""),
                    "description": (info.get("description") or "")[:300],
                    "tags": info.get("tags", []) if isinstance(info.get("tags"), list) else [],
                    "matcher": data.get("matcher-name") or data.get("extracted-results", [""])[0] if data.get("extracted-results") else "",
                })
            except (json.JSONDecodeError, KeyError, IndexError):
                continue

        logger.info(f"[Nuclei] Scan complete — {len(findings)} findings")
        return findings

    except Exception as e:
        logger.warning(f"[Nuclei] Scan failed: {e}")
        return []
