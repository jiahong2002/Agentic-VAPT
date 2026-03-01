from models import SurfaceReport


# Security headers that should be present
REQUIRED_HEADERS = {
    "content-security-policy": "Content Security Policy (CSP) missing — allows XSS attacks",
    "strict-transport-security": "HSTS missing — downgrade attacks possible",
    "x-frame-options": "X-Frame-Options missing — clickjacking possible",
    "x-content-type-options": "X-Content-Type-Options missing — MIME sniffing possible",
    "referrer-policy": "Referrer-Policy missing — information leakage possible",
    "permissions-policy": "Permissions-Policy missing — browser features uncontrolled",
}

DANGEROUS_RESPONSE_HEADERS = {
    "server": "Server header exposes version info",
    "x-powered-by": "X-Powered-By exposes technology stack",
}


def audit_headers(surface: SurfaceReport) -> list[dict]:
    """Return a list of header-based findings as notes for the Recon Agent."""
    findings = []
    headers_lower = {k.lower(): v for k, v in surface.headers.items()}

    for header, description in REQUIRED_HEADERS.items():
        if header not in headers_lower:
            findings.append({
                "type": "missing_header",
                "header": header,
                "description": description,
                "confirmed": True,  # deterministic
            })

    for header, description in DANGEROUS_RESPONSE_HEADERS.items():
        if header in headers_lower:
            findings.append({
                "type": "info_disclosure",
                "header": header,
                "value": headers_lower[header],
                "description": description,
                "confirmed": True,
            })

    return findings


def build_surface_notes(surface: SurfaceReport) -> str:
    """Build a rich textual summary of the surface report for the Recon Agent prompt."""
    lines = []
    lines.append(f"TARGET: {surface.target_url}")
    lines.append(f"\nDISCOVERED URLS ({len(surface.discovered_urls)}):")
    for url in surface.discovered_urls[:30]:
        lines.append(f"  - {url}")

    lines.append(f"\nFORMS ({len(surface.forms)}):")
    for form in surface.forms[:15]:
        inputs = ", ".join(f"{i.get('name','?')}({i.get('type','text')})" for i in form.get("inputs", []))
        lines.append(f"  - [{form.get('method','GET').upper()}] {form.get('action','?')} → inputs: {inputs} (from {form.get('source_url','?')})")

    lines.append(f"\nCOOKIES ({len(surface.cookies)}):")
    for c in surface.cookies[:10]:
        flags = []
        if not c.get("httpOnly"): flags.append("NO_HTTPONLY")
        if not c.get("secure"): flags.append("NO_SECURE")
        if not c.get("sameSite") or c.get("sameSite") == "None": flags.append("SAMESITE_NONE")
        lines.append(f"  - {c.get('name','?')}={str(c.get('value',''))[:20]}... flags: {', '.join(flags) or 'OK'}")

    lines.append(f"\nRESPONSE HEADERS:")
    for k, v in surface.headers.items():
        lines.append(f"  - {k}: {v}")

    lines.append(f"\nTECH STACK: {', '.join(surface.tech_stack) or 'Unknown'}")

    lines.append(f"\nJS ENDPOINTS ({len(surface.js_endpoints)}):")
    for ep in surface.js_endpoints[:20]:
        lines.append(f"  - {ep}")

    header_findings = audit_headers(surface)
    if header_findings:
        lines.append(f"\nSECURITY HEADER ISSUES ({len(header_findings)}):")
        for f in header_findings:
            lines.append(f"  - {f['description']}")

    if surface.scanner_findings:
        lines.append(f"\nACTIVE SCANNER FINDINGS — NUCLEI ({len(surface.scanner_findings)}):")
        lines.append("  These are confirmed detections from automated template matching — treat as high-signal:")
        for f in surface.scanner_findings:
            line = f"  [{f.get('severity','?')}] {f.get('name','?')} @ {f.get('url','?')}"
            if f.get("template_id"):
                line += f" (template: {f['template_id']})"
            lines.append(line)
            if f.get("description"):
                lines.append(f"    → {f['description'][:200]}")
            if f.get("matcher"):
                lines.append(f"    → Matched: {str(f['matcher'])[:100]}")
    else:
        lines.append(f"\nACTIVE SCANNER: No Nuclei findings (scanner not installed or no templates matched).")

    lines.append(f"\nCRAWLER NOTES:")
    for n in surface.notes[:10]:
        lines.append(f"  - {n}")

    return "\n".join(lines)
