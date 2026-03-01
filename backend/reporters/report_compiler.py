import os
import base64
from datetime import datetime
from models import ScanState, AgentStatus, Severity


SEVERITY_ORDER = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]

TEMPLATE_STR = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Security Assessment Report — {{ scan.target_url }}</title>
<style>
  /* ── Reset & base ── */
  *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
  html { font-size: 14px; }
  body {
    background: #ffffff;
    color: #1a1a2e;
    font-family: 'Segoe UI', Arial, system-ui, sans-serif;
    line-height: 1.65;
    -webkit-print-color-adjust: exact;
    print-color-adjust: exact;
  }

  /* ── Layout ── */
  .page { max-width: 920px; margin: 0 auto; padding: 48px 40px; }

  /* ── Cover / Header ── */
  .cover {
    background: linear-gradient(135deg, #0f172a 0%, #1e293b 60%, #0f2744 100%);
    border-radius: 16px;
    padding: 56px 48px;
    margin-bottom: 48px;
    color: #f8fafc;
    position: relative;
    overflow: hidden;
  }
  .cover::before {
    content: '';
    position: absolute; top: 0; right: 0; bottom: 0; left: 0;
    background: url("data:image/svg+xml,%3Csvg width='60' height='60' viewBox='0 0 60 60' xmlns='http://www.w3.org/2000/svg'%3E%3Cg fill='none' fill-rule='evenodd'%3E%3Cg fill='%2306b6d4' fill-opacity='0.04'%3E%3Cpath d='M36 34v-4h-2v4h-4v2h4v4h2v-4h4v-2h-4zm0-30V0h-2v4h-4v2h4v4h2V6h4V4h-4zM6 34v-4H4v4H0v2h4v4h2v-4h4v-2H6zM6 4V0H4v4H0v2h4v4h2V6h4V4H6z'/%3E%3C/g%3E%3C/g%3E%3C/svg%3E");
    opacity: 0.6;
  }
  .cover-content { position: relative; z-index: 1; }
  .cover-badge {
    display: inline-block;
    background: rgba(6,182,212,0.2);
    border: 1px solid rgba(6,182,212,0.4);
    color: #06b6d4;
    font-size: 10px;
    letter-spacing: 3px;
    text-transform: uppercase;
    padding: 5px 14px;
    border-radius: 999px;
    margin-bottom: 20px;
    font-weight: 700;
  }
  .cover h1 { font-size: 34px; font-weight: 800; margin-bottom: 10px; color: #f8fafc; }
  .cover-target {
    font-size: 16px;
    color: #94a3b8;
    margin-bottom: 32px;
    word-break: break-all;
  }
  .cover-target strong { color: #06b6d4; }
  .cover-meta-grid { display: grid; grid-template-columns: repeat(3, 1fr); gap: 20px; }
  .cover-meta-item {}
  .cover-meta-label { font-size: 10px; letter-spacing: 2px; text-transform: uppercase; color: #64748b; margin-bottom: 4px; }
  .cover-meta-value { font-size: 14px; color: #e2e8f0; font-weight: 600; }

  /* ── Risk Summary Tiles ── */
  .risk-grid { display: grid; grid-template-columns: repeat(5, 1fr); gap: 14px; margin-bottom: 48px; }
  .risk-tile {
    border-radius: 12px;
    padding: 18px 12px;
    text-align: center;
    border: 1px solid;
  }
  .risk-tile .count { font-size: 32px; font-weight: 900; line-height: 1; }
  .risk-tile .sev-label { font-size: 10px; letter-spacing: 2px; text-transform: uppercase; margin-top: 6px; font-weight: 700; }
  .tile-CRITICAL { background: rgba(220,38,38,0.08); border-color: rgba(220,38,38,0.25); }
  .tile-CRITICAL .count { color: #dc2626; }
  .tile-CRITICAL .sev-label { color: #dc2626; }
  .tile-HIGH { background: rgba(234,88,12,0.08); border-color: rgba(234,88,12,0.25); }
  .tile-HIGH .count { color: #ea580c; }
  .tile-HIGH .sev-label { color: #ea580c; }
  .tile-MEDIUM { background: rgba(202,138,4,0.08); border-color: rgba(202,138,4,0.25); }
  .tile-MEDIUM .count { color: #ca8a04; }
  .tile-MEDIUM .sev-label { color: #ca8a04; }
  .tile-LOW { background: rgba(22,163,74,0.08); border-color: rgba(22,163,74,0.25); }
  .tile-LOW .count { color: #16a34a; }
  .tile-LOW .sev-label { color: #16a34a; }
  .tile-INFO { background: rgba(37,99,235,0.08); border-color: rgba(37,99,235,0.25); }
  .tile-INFO .count { color: #2563eb; }
  .tile-INFO .sev-label { color: #2563eb; }

  /* ── Section headings ── */
  .section { margin-bottom: 48px; }
  .section-heading {
    font-size: 11px;
    letter-spacing: 3px;
    text-transform: uppercase;
    color: #64748b;
    margin-bottom: 20px;
    padding-bottom: 10px;
    border-bottom: 1px solid #e2e8f0;
    font-weight: 700;
  }

  /* ── Executive Summary ── */
  .exec-box {
    background: #f8fafc;
    border: 1px solid #e2e8f0;
    border-left: 4px solid #06b6d4;
    border-radius: 0 12px 12px 0;
    padding: 20px 24px;
    font-size: 14px;
    color: #374151;
    line-height: 1.7;
    margin-bottom: 16px;
  }
  .exec-box p { margin-bottom: 10px; }
  .exec-box p:last-child { margin-bottom: 0; }

  /* ── Methodology & Scope ── */
  .two-col { display: grid; grid-template-columns: 1fr 1fr; gap: 20px; margin-bottom: 32px; }
  .info-card {
    background: #f8fafc;
    border: 1px solid #e2e8f0;
    border-radius: 12px;
    padding: 18px 20px;
  }
  .info-card h4 { font-size: 12px; letter-spacing: 1.5px; text-transform: uppercase; color: #64748b; margin-bottom: 12px; font-weight: 700; }
  .info-card ul { list-style: none; }
  .info-card ul li { font-size: 13px; color: #374151; padding: 3px 0; padding-left: 16px; position: relative; }
  .info-card ul li::before { content: '→'; position: absolute; left: 0; color: #06b6d4; font-size: 11px; top: 4px; }

  /* ── Tech stack ── */
  .badges { display: flex; flex-wrap: wrap; gap: 8px; }
  .badge {
    background: #e0f2fe;
    color: #0369a1;
    border: 1px solid #bae6fd;
    border-radius: 999px;
    font-size: 12px;
    font-weight: 600;
    padding: 4px 14px;
  }
  .badge-empty { color: #94a3b8; font-size: 13px; font-style: italic; }

  /* ── Discovered URLs ── */
  .url-table { width: 100%; border-collapse: collapse; font-size: 13px; }
  .url-table thead th {
    text-align: left;
    font-size: 10px;
    letter-spacing: 2px;
    text-transform: uppercase;
    color: #64748b;
    padding: 8px 12px;
    border-bottom: 1px solid #e2e8f0;
    font-weight: 700;
  }
  .url-table tbody tr:nth-child(even) { background: #f8fafc; }
  .url-table tbody td { padding: 7px 12px; color: #374151; word-break: break-all; border-bottom: 1px solid #f1f5f9; }
  .url-table tbody td:first-child { font-family: 'Courier New', monospace; font-size: 12px; color: #0f172a; }

  /* ── Finding cards ── */
  .finding {
    border: 1px solid #e2e8f0;
    border-radius: 14px;
    margin-bottom: 36px;
    overflow: hidden;
    box-shadow: 0 1px 6px rgba(0,0,0,0.06);
  }
  .finding-header {
    display: flex;
    align-items: center;
    gap: 14px;
    padding: 18px 22px;
    border-bottom: 1px solid #e2e8f0;
    background: #f8fafc;
  }
  .sev-badge {
    padding: 4px 12px;
    border-radius: 999px;
    font-size: 10px;
    font-weight: 800;
    letter-spacing: 1.5px;
    text-transform: uppercase;
    white-space: nowrap;
  }
  .sev-CRITICAL { background: rgba(220,38,38,0.1); color: #dc2626; border: 1px solid rgba(220,38,38,0.3); }
  .sev-HIGH { background: rgba(234,88,12,0.1); color: #ea580c; border: 1px solid rgba(234,88,12,0.3); }
  .sev-MEDIUM { background: rgba(202,138,4,0.1); color: #ca8a04; border: 1px solid rgba(202,138,4,0.3); }
  .sev-LOW { background: rgba(22,163,74,0.1); color: #16a34a; border: 1px solid rgba(22,163,74,0.3); }
  .sev-INFO { background: rgba(37,99,235,0.1); color: #2563eb; border: 1px solid rgba(37,99,235,0.3); }
  .finding-title { font-size: 17px; font-weight: 700; flex: 1; color: #0f172a; }
  .confirmed-badge {
    background: rgba(5,150,105,0.1);
    color: #059669;
    border: 1px solid rgba(5,150,105,0.3);
    padding: 3px 12px;
    border-radius: 4px;
    font-size: 11px;
    font-weight: 700;
    white-space: nowrap;
  }
  .unconfirmed-badge {
    background: rgba(100,116,139,0.1);
    color: #64748b;
    border: 1px solid rgba(100,116,139,0.3);
    padding: 3px 12px;
    border-radius: 4px;
    font-size: 11px;
    font-weight: 700;
  }
  .cvss-badge {
    font-size: 12px;
    color: #64748b;
    font-weight: 600;
    white-space: nowrap;
  }
  .finding-body { padding: 22px; }
  .technique-tag {
    display: inline-block;
    background: #ede9fe;
    color: #6d28d9;
    border: 1px solid #ddd6fe;
    border-radius: 4px;
    font-size: 11px;
    font-weight: 600;
    padding: 2px 10px;
    margin-bottom: 12px;
    letter-spacing: 0.5px;
  }
  .summary-text { font-size: 14px; color: #374151; line-height: 1.65; margin-bottom: 16px; }

  /* ── Reproduction steps ── */
  .steps-heading {
    font-size: 10px;
    letter-spacing: 2px;
    text-transform: uppercase;
    color: #64748b;
    margin-bottom: 16px;
    margin-top: 20px;
    font-weight: 700;
  }
  .steps { list-style: none; }
  .step { margin-bottom: 28px; }
  .step-header { display: flex; align-items: flex-start; gap: 12px; margin-bottom: 10px; }
  .step-num {
    width: 28px; height: 28px; min-width: 28px;
    background: #06b6d4; color: #fff;
    border-radius: 50%;
    display: flex; align-items: center; justify-content: center;
    font-size: 12px; font-weight: 800;
  }
  .step-desc { font-size: 14px; font-weight: 600; color: #1e293b; padding-top: 3px; }
  .step-body { margin-left: 40px; }
  .step-label { font-size: 9px; letter-spacing: 2px; text-transform: uppercase; color: #94a3b8; margin-bottom: 5px; margin-top: 12px; font-weight: 700; }

  /* Terminal */
  .terminal { background: #0d1117; border: 1px solid #30363d; border-radius: 8px; overflow: hidden; margin-top: 4px; }
  .terminal-bar { background: #161b22; padding: 6px 12px; display: flex; align-items: center; gap: 6px; border-bottom: 1px solid #30363d; }
  .dot { width: 10px; height: 10px; border-radius: 50%; }
  .dot-r { background: #ff5f57; }
  .dot-y { background: #febc2e; }
  .dot-g { background: #28c840; }
  .terminal-lbl { font-size: 11px; color: #6b7280; margin-left: 4px; font-family: monospace; }
  .terminal-body { padding: 12px 16px; }
  .terminal-cmd { font-size: 12px; font-family: 'Courier New', monospace; color: #4ade80; word-break: break-all; white-space: pre-wrap; }
  .terminal-cmd::before { content: "$ "; color: #6b7280; }
  .terminal-out { font-size: 11px; font-family: 'Courier New', monospace; color: #cbd5e1; word-break: break-all; white-space: pre-wrap; border-top: 1px solid #30363d; margin-top: 10px; padding-top: 10px; }

  /* Code action */
  .step-action {
    font-size: 12px; font-family: 'Courier New', monospace;
    background: #f1f5f9; border: 1px solid #e2e8f0;
    padding: 8px 12px; border-radius: 6px;
    display: block; color: #1d4ed8;
    word-break: break-all; margin-top: 4px;
  }
  /* Screenshot */
  .step-screenshot {
    width: 100%; border-radius: 8px;
    border: 1px solid #e2e8f0;
    margin-top: 12px; display: block;
    box-shadow: 0 2px 8px rgba(0,0,0,0.12);
  }
  /* Evidence */
  .evidence-label { font-size: 9px; letter-spacing: 2px; text-transform: uppercase; color: #94a3b8; margin-top: 12px; margin-bottom: 4px; font-weight: 700; }
  .evidence {
    font-size: 13px; color: #475569;
    background: #f8fafc;
    border-left: 3px solid #06b6d4;
    padding: 8px 14px;
    border-radius: 0 6px 6px 0;
  }

  /* ── Remediation ── */
  .remediation-box {
    background: #f0fdf4;
    border: 1px solid #bbf7d0;
    border-radius: 8px;
    padding: 14px 18px;
    margin-top: 16px;
    font-size: 13px;
    color: #166534;
    line-height: 1.6;
  }
  .remediation-box strong { display: block; margin-bottom: 6px; font-size: 10px; letter-spacing: 2px; text-transform: uppercase; color: #16a34a; font-weight: 700; }

  /* ── False positive ── */
  .fp-box {
    background: #f8fafc;
    border: 1px solid #e2e8f0;
    border-radius: 8px;
    padding: 14px 18px;
    margin-top: 12px;
    font-size: 13px;
    color: #64748b;
  }

  /* ── Footer ── */
  .footer {
    border-top: 1px solid #e2e8f0;
    padding-top: 24px;
    margin-top: 56px;
    display: flex;
    justify-content: space-between;
    font-size: 12px;
    color: #94a3b8;
  }

  /* ── Page breaks for print/PDF ── */
  @media print {
    .finding { page-break-inside: avoid; }
    .cover { page-break-after: always; }
  }
</style>
</head>
<body>
<div class="page">

  <!-- ══ COVER ══ -->
  <div class="cover">
    <div class="cover-content">
      <div class="cover-badge">Confidential Security Assessment</div>
      <h1>Vulnerability Assessment Report</h1>
      <div class="cover-target">Target: <strong>{{ scan.target_url }}</strong></div>
      <div class="cover-meta-grid">
        <div class="cover-meta-item">
          <div class="cover-meta-label">Generated</div>
          <div class="cover-meta-value">{{ generated_at }}</div>
        </div>
        <div class="cover-meta-item">
          <div class="cover-meta-label">Scan ID</div>
          <div class="cover-meta-value" style="font-family:monospace;font-size:12px;">{{ scan.scan_id }}</div>
        </div>
        <div class="cover-meta-item">
          <div class="cover-meta-label">Total Findings</div>
          <div class="cover-meta-value">{{ scan.agent_results|length }} investigated</div>
        </div>
      </div>
    </div>
  </div>

  <!-- ══ RISK SUMMARY ══ -->
  <div class="section">
    <div class="section-heading">Risk Summary</div>
    <div class="risk-grid">
      {% for sev in ['CRITICAL','HIGH','MEDIUM','LOW','INFO'] %}
      <div class="risk-tile tile-{{ sev }}">
        <div class="count">{{ severity_counts[sev] }}</div>
        <div class="sev-label">{{ sev }}</div>
      </div>
      {% endfor %}
    </div>
  </div>

  <!-- ══ EXECUTIVE SUMMARY ══ -->
  <div class="section">
    <div class="section-heading">Executive Summary</div>
    <div class="exec-box">
      <p>
        An automated penetration test was conducted against <strong>{{ scan.target_url }}</strong> using a multi-agent
        AI-driven framework. The assessment employed dynamic crawling followed by hypothesis-driven exploitation
        agents to identify and verify vulnerabilities across {{ scan.agent_results|length }} attack vectors.
      </p>
      <p>
        Of the {{ scan.agent_results|length }} techniques investigated, <strong>{{ confirmed_count }} were confirmed
        exploitable</strong>{% if confirmed_count == 0 %}, representing no immediately exploitable attack paths{% else %}
        — posing active risk to the confidentiality, integrity, or availability of the application{% endif %}.
        {% if severity_counts['CRITICAL'] > 0 %}
        <strong>{{ severity_counts['CRITICAL'] }} critical-severity vulnerabilities</strong> were identified and require
        immediate remediation.
        {% elif severity_counts['HIGH'] > 0 %}
        <strong>{{ severity_counts['HIGH'] }} high-severity vulnerabilities</strong> were identified and should be
        addressed as a priority.
        {% endif %}
      </p>
      <p>
        This report documents each finding with reproduction steps, evidence, and actionable remediation guidance.
        All testing was conducted in a controlled environment against a locally hosted target. All findings should be
        verified by a qualified security engineer before remediation is undertaken.
      </p>
    </div>
  </div>

  <!-- ══ SCOPE & METHODOLOGY ══ -->
  <div class="section">
    <div class="section-heading">Scope &amp; Methodology</div>
    <div class="two-col">
      <div class="info-card">
        <h4>Scope</h4>
        <ul>
          <li>Target: {{ scan.target_url }}</li>
          <li>{{ scan.surface_report.discovered_urls|length if scan.surface_report else '?' }} URLs discovered via crawl</li>
          <li>{{ scan.surface_report.forms|length if scan.surface_report else '?' }} forms enumerated</li>
          <li>Black-box testing (no source code access)</li>
          <li>Authenticated &amp; unauthenticated surfaces</li>
        </ul>
      </div>
      <div class="info-card">
        <h4>Methodology</h4>
        <ul>
          <li>Phase 1: Automated surface crawl (Playwright)</li>
          <li>Phase 2: Recon agent — hypothesis generation</li>
          <li>Phase 3: Exploit agents — ReAct loop testing</li>
          <li>Techniques: OWASP Top 10 &amp; beyond</li>
          <li>Evidence: screenshots + HTTP traces</li>
        </ul>
      </div>
    </div>
  </div>

  <!-- ══ TECHNOLOGY STACK ══ -->
  {% if scan.surface_report and scan.surface_report.tech_stack %}
  <div class="section">
    <div class="section-heading">Identified Technology Stack</div>
    <div class="badges">
      {% for tech in scan.surface_report.tech_stack %}
      <span class="badge">{{ tech }}</span>
      {% endfor %}
    </div>
  </div>
  {% endif %}

  <!-- ══ DISCOVERED URLS ══ -->
  {% if scan.surface_report and scan.surface_report.discovered_urls %}
  <div class="section">
    <div class="section-heading">Discovered Attack Surface — URLs ({{ scan.surface_report.discovered_urls|length }})</div>
    <table class="url-table">
      <thead>
        <tr>
          <th>#</th>
          <th>URL</th>
        </tr>
      </thead>
      <tbody>
        {% for url in scan.surface_report.discovered_urls[:40] %}
        <tr>
          <td style="width:40px;color:#94a3b8;font-family:monospace;">{{ loop.index }}</td>
          <td>{{ url }}</td>
        </tr>
        {% endfor %}
        {% if scan.surface_report.discovered_urls|length > 40 %}
        <tr>
          <td></td>
          <td style="color:#94a3b8;font-style:italic;">… and {{ scan.surface_report.discovered_urls|length - 40 }} more URLs</td>
        </tr>
        {% endif %}
      </tbody>
    </table>
  </div>
  {% endif %}

  <!-- ══ FINDINGS ══ -->
  <div class="section">
    <div class="section-heading">Detailed Findings ({{ scan.agent_results|length }})</div>

    {% for result in scan.agent_results %}
    <div class="finding">
      <div class="finding-header">
        <span class="sev-badge sev-{{ result.severity.value }}">{{ result.severity.value }}</span>
        <span class="finding-title">{{ result.hypothesis_title }}</span>
        {% if result.status.value == 'CONFIRMED' %}
          <span class="confirmed-badge">&#10003; Confirmed</span>
        {% else %}
          <span class="unconfirmed-badge">? Unconfirmed</span>
        {% endif %}
        {% if result.cvss_score %}
          <span class="cvss-badge">CVSS&nbsp;{{ result.cvss_score }}</span>
        {% endif %}
      </div>

      <div class="finding-body">
        <span class="technique-tag">{{ result.technique }}</span>

        {% if result.summary %}
          <p class="summary-text">{{ result.summary }}</p>
        {% endif %}

        <!-- ── Confirmed: steps ── -->
        {% if result.status.value == 'CONFIRMED' and result.steps %}
          <div class="steps-heading">Reproduction Steps</div>
          <ol class="steps">
            {% for step in result.steps %}
            <li class="step">
              <div class="step-header">
                <div class="step-num">{{ step.step_number }}</div>
                <div class="step-desc">{{ step.description }}</div>
              </div>
              <div class="step-body">
                {% if step.action %}
                  <div class="step-label">Action</div>
                  {% if step.action.startswith('curl') %}
                    <div class="terminal">
                      <div class="terminal-bar">
                        <div class="dot dot-r"></div>
                        <div class="dot dot-y"></div>
                        <div class="dot dot-g"></div>
                        <span class="terminal-lbl">bash</span>
                      </div>
                      <div class="terminal-body">
                        <div class="terminal-cmd">{{ step.action }}</div>
                        {% if step.response_evidence %}
                          <div class="terminal-out">{{ step.response_evidence }}</div>
                        {% endif %}
                      </div>
                    </div>
                  {% else %}
                    <code class="step-action">{{ step.action }}</code>
                    {% if step.screenshot_path and step.screenshot_path in screenshots %}
                      <img class="step-screenshot"
                           src="data:image/png;base64,{{ screenshots[step.screenshot_path] }}"
                           alt="Step {{ step.step_number }}" />
                    {% endif %}
                    {% if step.response_evidence %}
                      <div class="evidence-label">Observed Result</div>
                      <div class="evidence">{{ step.response_evidence }}</div>
                    {% endif %}
                  {% endif %}
                {% endif %}
              </div>
            </li>
            {% endfor %}
          </ol>

        <!-- ── Unconfirmed ── -->
        {% elif result.status.value == 'UNCONFIRMED' %}
          <div class="fp-box">
            <strong style="display:inline;color:#475569;">&#9888; Not Exploited</strong>&nbsp;
            This technique was investigated but could not be automatically verified as exploitable.
            {% if result.false_positive_reason %}
              Reason: {{ result.false_positive_reason }}
            {% endif %}
          </div>
        {% endif %}

        {% if result.remediation %}
          <div class="remediation-box">
            <strong>Remediation Guidance</strong>
            {{ result.remediation }}
          </div>
        {% endif %}
      </div>
    </div>
    {% endfor %}
  </div>

  <!-- ══ FOOTER ══ -->
  <div class="footer">
    <span>Generated by PenTest Agent &bull; DLWeek '25 Hackathon &bull; For authorized testing only</span>
    <span>{{ generated_at }}</span>
  </div>

</div>
</body>
</html>"""


def compile_report(scan_state: ScanState) -> str:
    """Compile all agent results into a detailed HTML report with embedded screenshots."""
    # Load screenshots as base64
    screenshots: dict[str, str] = {}
    for result in scan_state.agent_results:
        for path in result.screenshot_paths:
            if path and os.path.exists(path) and path not in screenshots:
                with open(path, "rb") as f:
                    screenshots[path] = base64.b64encode(f.read()).decode()

        for step in result.steps:
            if step.screenshot_path and os.path.exists(step.screenshot_path):
                if step.screenshot_path not in screenshots:
                    with open(step.screenshot_path, "rb") as f:
                        screenshots[step.screenshot_path] = base64.b64encode(f.read()).decode()

    # Count severities
    severity_counts = {s.value: 0 for s in Severity}
    confirmed_count = 0
    for r in scan_state.agent_results:
        severity_counts[r.severity.value] += 1
        if r.status == AgentStatus.CONFIRMED:
            confirmed_count += 1

    # Sort results: confirmed first, then by severity
    sev_order = {s.value: i for i, s in enumerate(SEVERITY_ORDER)}
    sorted_results = sorted(
        scan_state.agent_results,
        key=lambda r: (0 if r.status == AgentStatus.CONFIRMED else 1, sev_order.get(r.severity.value, 99)),
    )
    scan_state_copy = scan_state.model_copy(update={"agent_results": sorted_results})

    from jinja2 import Template
    template = Template(TEMPLATE_STR)
    html = template.render(
        scan=scan_state_copy,
        generated_at=datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC"),
        screenshots=screenshots,
        severity_counts=severity_counts,
        confirmed_count=confirmed_count,
    )
    return html
