import type { ExploitCandidate } from "../store/scanStore.js";

export const PHASE_PROMPTS = {
  recon: (targetUrl: string) => `
You are a professional security researcher conducting authorized penetration testing on a target web application.

Target URL: ${targetUrl}

## PHASE 1: RECONNAISSANCE & SCANNING

Use the available MCP tools to perform a thorough reconnaissance. Follow these steps IN ORDER:

**Step 1** - Call crawl_site:
- url: "${targetUrl}"
- max_depth: 2
- max_pages: 30

**Step 2** - Call test_security_headers:
- url: "${targetUrl}"

**Step 3** - Call test_file_exposure:
- base_url: "${targetUrl}"

After all three tools complete, analyze the results and produce your findings as a JSON object with this EXACT structure (no markdown, just the raw JSON):

{
  "target": "${targetUrl}",
  "pages_found": <number>,
  "technologies_detected": ["<tech1>", "<tech2>"],
  "forms_found": [
    { "url": "<action_url>", "method": "GET|POST", "params": ["<param1>", "<param2>"] }
  ],
  "exposed_files": [
    { "path": "<path>", "severity": "critical|high|medium|low", "description": "<desc>" }
  ],
  "header_issues": [
    { "header": "<header_name>", "issue": "<issue_description>", "severity": "high|medium|low" }
  ],
  "exploit_candidates": [
    {
      "type": "sqli|xss|file_exposure|header",
      "endpoint": "<full_url>",
      "param": "<parameter_name_or_path>",
      "method": "GET|POST",
      "description": "<what_to_test_and_why>",
      "priority": "high|medium|low"
    }
  ],
  "summary": "<2-3 sentence human-readable summary of what was found>"
}

Be thorough. Only include real findings from the tool results. List ALL forms found as sqli AND xss candidates.
Output ONLY the JSON, nothing else.
`,

  exploit: (candidate: ExploitCandidate) => {
    if (candidate.type === "sqli") {
      return `
You are conducting an authorized SQL injection test.

Target: ${candidate.endpoint}
Parameter: ${candidate.param}
Method: ${candidate.method}
Description: ${candidate.description}

Call test_sqli with:
- url: "${candidate.endpoint}"
- method: "${candidate.method}"
- param_name: "${candidate.param}"
- baseline_value: "1"

After the tool returns, output ONLY a JSON object. The evidence_steps must be written so that any developer can reproduce the attack from scratch. Use exactly 4 steps in this order: request setup, exact injected payload, exact observed response, and why the response confirms SQLi. In each step, explain what is happening in plain language (not just what command was run). Include the EXACT payload used, the EXACT server response text (error message, response time, boolean difference), and a clear technical explanation. The reproduction field must be a complete curl command someone can copy-paste into a terminal.

{
  "type": "sqli",
  "endpoint": "${candidate.endpoint}",
  "param": "${candidate.param}",
  "vulnerable": <true|false>,
  "technique": "<error-based|boolean-based|time-based|null>",
  "payload": "<exact working payload, e.g. ' OR '1'='1 or 1' AND SLEEP(5)-->",
  "evidence": "<one-line human-readable summary>",
  "evidence_steps": [
    "Step 1: Request setup — Sent ${candidate.method} request to ${candidate.endpoint} targeting parameter ${candidate.param}",
    "Step 2: Payload used — ${candidate.param}=<EXACT_PAYLOAD_HERE> (URL-encoded if needed)",
    "Step 3: Observed response — HTTP <STATUS> with exact evidence: <PASTE exact error message, timing difference, or true/false content difference>",
    "Step 4: Why this proves SQLi — <technical reason tied to Step 3 evidence>"
  ],
  "reproduction": "curl -s '<FULL_URL_WITH_PAYLOAD_IN_QUERYSTRING_OR_-d_FOR_POST>'",
  "severity": "critical|high|medium|low",
  "remediation": "<specific remediation advice — parameterised queries, ORM, input validation>"
}
Output ONLY the JSON.
`;
    }

    if (candidate.type === "xss") {
      return `
You are conducting an authorized XSS (Cross-Site Scripting) test.

Target: ${candidate.endpoint}
Parameter: ${candidate.param}
Method: ${candidate.method}
Description: ${candidate.description}

Call test_xss with:
- url: "${candidate.endpoint}"
- method: "${candidate.method}"
- param_name: "${candidate.param}"

After the tool returns, output ONLY a JSON object. The evidence_steps must be written so that any developer can reproduce the attack from scratch. Use exactly 4 steps in this order: request setup, exact injected payload, exact observed response, and why the response confirms XSS. In each step, explain what is happening in plain language (not just what command was run). The reproduction field must be a complete curl command someone can copy-paste into a terminal.
{
  "type": "xss",
  "endpoint": "${candidate.endpoint}",
  "param": "${candidate.param}",
  "vulnerable": <true|false>,
  "xss_type": "reflected|stored|null",
  "payload": "<working_payload_or_null>",
  "evidence": "<one-line summary of what proved the vulnerability>",
  "evidence_steps": [
    "Step 1: Request setup — Sent ${candidate.method} request to ${candidate.endpoint} targeting parameter ${candidate.param}",
    "Step 2: Payload used — ${candidate.param}=<EXACT_XSS_PAYLOAD>",
    "Step 3: Observed response — HTTP <STATUS> with exact reflection evidence: <exact reflected snippet showing unescaped payload>",
    "Step 4: Why this proves XSS — <technical reason tied to Step 3 evidence>"
  ],
  "reproduction": "curl -s '<FULL_URL_WITH_PAYLOAD_IN_QUERYSTRING_OR_-d_FOR_POST>'",
  "severity": "high|medium|low",
  "remediation": "<specific remediation advice>"
}
Output ONLY the JSON.
`;
    }

    // file_exposure or header — no additional tool call needed
    return `
The following vulnerability was identified during reconnaissance:

Type: ${candidate.type}
Endpoint: ${candidate.endpoint}
Description: ${candidate.description}

Output ONLY a JSON object summarizing this finding:
{
  "type": "${candidate.type}",
  "endpoint": "${candidate.endpoint}",
  "param": "${candidate.param}",
  "vulnerable": true,
  "payload": null,
  "evidence": "${candidate.description}",
  "evidence_steps": [
    "Step 1: Request setup — Sent ${candidate.method} request to ${candidate.endpoint} for ${candidate.param}",
    "Step 2: Probe used — Requested resource/path exactly as discovered during reconnaissance",
    "Step 3: Observed response — Server response confirmed issue: ${candidate.description}",
    "Step 4: Why this is vulnerable — ${candidate.type} misconfiguration exposes attack surface or sensitive data"
  ],
  "reproduction": "curl -i '${candidate.endpoint}'",
  "severity": "${candidate.priority === "high" ? "high" : "medium"}",
  "remediation": "<specific remediation advice for this type of issue>"
}
Output ONLY the JSON.
`;
  },

  report: (reconJson: string, exploitResults: string) => `
You are a professional security researcher writing a penetration test report.

## Reconnaissance Findings:
${reconJson}

## Exploitation Results:
${exploitResults}

Generate a comprehensive security assessment report as a JSON object with this EXACT structure:

For each finding, preserve reproducibility details from exploitation results. Do not generalize away concrete evidence. Keep payloads, evidence_steps, and reproduction commands specific and copy-pastable. Evidence steps must clearly tell the reader both what to do and what is happening at each step.

{
  "summary": {
    "scan_date": "${new Date().toISOString()}",
    "total_findings": <number>,
    "critical": <number>,
    "high": <number>,
    "medium": <number>,
    "low": <number>
  },
  "executive_summary": "<3-4 sentence paragraph describing overall security posture and most critical issues>",
  "findings": [
    {
      "id": "VULN-001",
      "type": "<sqli|xss|file_exposure|header>",
      "title": "<short descriptive title>",
      "severity": "critical|high|medium|low",
      "endpoint": "<url>",
      "description": "<detailed description of the vulnerability>",
      "evidence": "<proof that the vulnerability exists>",
      "evidence_steps": [
        "Step 1: <request setup>",
        "Step 2: <exact payload/probe used>",
        "Step 3: <exact observed response evidence>",
        "Step 4: <why it proves exploitability>"
      ],
      "payload": "<payload that triggered it, or null>",
      "reproduction": "<copy-paste curl command, or null>",
      "remediation": "<specific step-by-step fix>",
      "references": ["<OWASP or CVE reference>"]
    }
  ],
  "recommendations": [
    "<prioritized actionable recommendation 1>",
    "<prioritized actionable recommendation 2>",
    "<prioritized actionable recommendation 3>"
  ]
}

Order findings by severity (critical first). Only include findings where vulnerable=true from exploit results, plus any confirmed header/file exposure issues.
Output ONLY the JSON.
`,
};
